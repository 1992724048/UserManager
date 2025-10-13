#pragma once
#include "util.h"
#include <cstddef>

struct FileDate {
    std::basic_string<char, std::char_traits<char>, util::JemallocAllocator<char>> data;
    std::chrono::system_clock::time_point read_time;
    std::size_t size;
    std::size_t revc_count;
};

class TBBThreadPool final : public httplib::TaskQueue {
public:
    explicit TBBThreadPool(const int threads = std::thread::hardware_concurrency()) {
        ta.initialize(threads);
    }

    auto enqueue(std::function<void()> fn) -> bool override {
        ta.execute([&] {
            tg.run(fn);
        });
        return true;
    }

    auto shutdown() -> void override {
        tg.wait();
    }

    auto max() const -> int {
        return ta.max_concurrency();
    }

    ~TBBThreadPool() override {
        shutdown();
    }

private:
    tbb::task_arena ta;
    tbb::task_group tg;
};

class Service {
    TEvent<> config_updata;
    util::Timer cookie_timer;
    util::Timer file_cache_timer;
    tbb::global_control gc{tbb::global_control::max_allowed_parallelism,
                           std::thread::hardware_concurrency() * 6
    };
    inline static std::pair<std::string, std::chrono::system_clock::time_point> active_sessions;
public:
    std::shared_ptr<tp::ThreadPool> thread_pool{
        nullptr
    };
    std::shared_ptr<httplib::SSLServer> server{
        nullptr
    };

    config::Field<int> f_server_port;
    config::Field<int> f_file_cache_time;
    config::Field<int> f_max_requests;
    config::Field<int> f_window_time;
    config::Field<int> f_max_download_speed;
    config::Field<bool> f_tbb_mode;
    config::Field<bool> f_file_cache;
    config::Field<std::size_t> f_sqlite_max_connect;
    config::Field<std::size_t> f_file_cache_max_size;
    config::Field<std::string> f_username;
    config::Field<std::string> f_password;
    config::Field<std::string> f_domain;
    config::Field<std::filesystem::path> f_cert_path;
    config::Field<std::filesystem::path> f_key_path;
    config::Field<std::filesystem::path> f_sql_path;
    config::Field<std::filesystem::path> f_web_files;
    config::Field<std::filesystem::path> f_files_path;
    config::Field<std::filesystem::path> f_web_error_page;
    config::Field<config::Enum<Logger::Level>> f_log_level;
    config::Field<config::Enum<Logger::LoggerType>> f_log_type;

    std::size_t file_total_size{};
    inline static util::SafeMap<std::string, FileDate> file_cache;
    inline static util::RateLimiter rate_limiter;

    static auto Instance() -> Service&;

    Service();
    ~Service();

    auto Run() const -> int;
    static auto CheckCookieValid(const httplib::Request& req) -> bool;
    static auto AddCookie() -> std::string;
};
