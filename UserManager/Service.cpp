#include "Service.h"
#include <ipp.h>

#include "Controller/HTTPController.h"
#include "Controller/app/AppController.h"
#include "Controller/data/DataController.h"
#include "Controller/key/KeyController.h"
#include "Controller/setting/SettingController.h"

#include "Dao/Dao.h"
#include <boost/regex.hpp>

#include "Controller/file/FileController.h"

auto Service::Instance() -> Service& {
    static Service instance;
    return instance;
}

Service::Service() : NFS(f_server_port, "", "server", 443),
                     NFS(f_file_cache_time, "", "server", std::chrono::duration_cast<std::chrono::seconds>(std::chrono::days(3)).count()),
                     NFS(f_max_download_speed, "", "server", 0.5 * 1024 * 1024),
                     NFS(f_tbb_mode, "", "server", true),
                     NFS(f_file_cache, "", "server", false),
                     NFS(f_sqlite_max_connect, "", "server", std::thread::hardware_concurrency() * 2),
                     NFS(f_file_cache_max_size, "", "server", std::numeric_limits<int>().max() / 16),
                     NFS(f_username, "", "admin", "admin"),
                     NFS(f_password, "", "admin", "admin123"),
                     NFS(f_domain, "", "server", "localhost"),
                     NFS(f_cert_path, "", "ca", util::app_path() / "SSL" / "cert.pem"),
                     NFS(f_key_path, "", "ca", util::app_path() / "SSL" / "key.pem"),
                     NFS(f_sql_path, "", "sql", util::app_path() / "SQL" / "sqlite.db"),
                     NFS(f_web_files, "", "server", util::app_path() / "web"),
                     NFS(f_files_path, "", "server", util::app_path() / "root"),
                     NFS(f_web_error_page, "", "server", util::app_path() / "web"/ "res" / "error.html"),
                     NFS(f_log_level, "", "log", Logger::Level::Trace),
                     NFS(f_log_type, "", "log", Logger::LoggerType::Any) {
    ippInit();

    cookie_timer.start(std::chrono::duration_cast<std::chrono::milliseconds>(1h).count(),
                       [this] {
                           const auto now = std::chrono::system_clock::now();
                           if (now > active_sessions.second) {
                               active_sessions = {};
                           }
                       });

    file_cache_timer.start(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::days(1)).count(),
                           [this] {
                               for (auto& [path, date] : file_cache) {
                                   if (std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now() - date.read_time).count() > f_file_cache_time) {
                                       file_cache.erase(path);
                                   }
                               }
                           });

    if (!is_directory(f_files_path)) {
        create_directories(f_files_path);
    }

    if (!is_directory(f_sql_path.value().parent_path() / "backup")) {
        create_directories(f_sql_path.value().parent_path() / "backup");
    }

    Logger::SetLevel(f_log_level, f_log_type);

    LOG_DEBUG << fmt::format("Cert 路径: {}", f_cert_path.value().string());
    LOG_DEBUG << fmt::format("Key  路径: {}", f_key_path.value().string());

    thread_pool = std::make_shared<tp::ThreadPool>(std::thread::hardware_concurrency());
    server = std::make_shared<httplib::SSLServer>(f_cert_path.value().string().data(), f_key_path.value().string().data());

    if (f_tbb_mode) {
        server->new_task_queue = [] {
            return new TBBThreadPool(std::thread::hardware_concurrency() * 2);
        };
    }

    server->set_error_handler([this](const httplib::Request& req, httplib::Response& res) {
        static const boost::regex pattern(R"(\$(status|message|ip|time|path|home|cookie|http)\$)", static_cast<boost::regex_constants::flag_type_>(boost::regex::perl | boost::regex::optimize));
        static const std::string error_template = util::read_file(f_web_error_page);

        auto format_time = []() -> std::string {
            using namespace std::chrono;

            const auto now = system_clock::now();
            const auto now_time_t = system_clock::to_time_t(now);

            std::tm tm_info;
            gmtime_s(&tm_info, &now_time_t);

            std::ostringstream oss;
            oss << std::put_time(&tm_info, "%Y-%m-%dT%H:%M:%S");

            const auto ms = duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;
            oss << '.' << std::setfill('0') << std::setw(3) << ms.count() << "Z";
            return oss.str();
        };

        std::map<std::string, std::function<std::string()>> replacements = {
            {
                "$status$",
                [&] -> std::string {
                    return std::to_string(res.status);
                }
            },
            {
                "$message$",
                [&] -> std::string {
                    return std::string(httplib::status_message(res.status));
                }
            },
            {
                "$ip$",
                [&] -> std::string {
                    return fmt::format("{}:{}", req.remote_addr, req.remote_port);
                }
            },
            {
                "$time$",
                [&] -> std::string {
                    return format_time();
                }
            },
            {
                "$path$",
                [&] -> std::string {
                    return req.path;
                }
            },
            {
                "$home$",
                [&] -> std::string {
                    return f_web_files.value().filename().string() + "/";
                }
            },
            {
                "$cookie$",
                [&] -> std::string {
                    return "";
                }
            },
            {
                "$http$",
                [&] -> std::string {
                    return f_domain;
                }
            }
        };

        const std::string buffer = boost::regex_replace(error_template,
                                                        pattern,
                                                        [&](const boost::smatch& match) -> std::string {
                                                            const auto& str = match[0].str();
                                                            return replacements.contains(str) ? replacements[str]() : str;
                                                        },
                                                        boost::format_all);

        res.set_content(buffer, "text/html");
    });

    server->set_logger([this](const httplib::Request& req, const httplib::Response& res) -> void {
        if (res.status >= 400 && res.status <= 600) {
            LOG_WARNING << fmt::format("{}:{} -> {} {} -> {}", req.remote_addr, req.remote_port, res.status, httplib::status_message(res.status), req.path);
        }
    });
}

Service::~Service() {
    file_cache_timer.stop();
    cookie_timer.stop();
    server->stop();
}

auto Service::Run() const -> int {
    Dao::init_date_base();
    httplib::HttpControllerBase::registerMethod();

    LOG_DEBUG << fmt::format("服务器网址: https://localhost:{}/", f_server_port.value());

    server->bind_to_port("0.0.0.0", f_server_port);
    return server->listen_after_bind();
}

auto Service::CheckCookieValid(const httplib::Request& req) -> bool {
    const std::string cookie = req.get_header_value("Cookie");
    if (cookie.empty()) {
        return false;
    }

    constexpr std::string_view token_prefix = "session_token=";
    const std::string_view cookie_view(cookie);
    const size_t pos = cookie_view.find(token_prefix);
    if (pos == std::string_view::npos) {
        return false;
    }

    const size_t start = pos + token_prefix.size();
    const size_t end = cookie_view.find(';', start);
    const std::string_view token = end == std::string_view::npos ? cookie_view.substr(start) : cookie_view.substr(start, end - start);

    if (active_sessions.first != token) {
        return false;
    }

    const auto now = std::chrono::system_clock::now();
    if (now < active_sessions.second) {
        return true;
    }

    active_sessions = {};
    return false;
}


auto Service::AddCookie() -> std::string {
    const std::string session_token = util::generate_session_token();
    const auto expiry_time = std::chrono::system_clock::now() + std::chrono::hours(72);

    active_sessions = {session_token, expiry_time};

    std::ostringstream oss;
    oss << "session_token=" << session_token << "; Path=/; HttpOnly; Secure; Expires=";

    const auto t = std::chrono::system_clock::to_time_t(expiry_time);

    std::tm tm;
    gmtime_s(&tm, &t);
    oss << std::put_time(&tm, "%a, %d %b %Y %H:%M:%S GMT");

    return oss.str();
}
