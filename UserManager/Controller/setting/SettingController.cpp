#include "SettingController.h"
#include "../../Service.h"
#include <config/fields/Enum.h>

namespace controller {
    SettingController::SettingController() {
    }

    auto SettingController::set_server(const httplib::Request& req, httplib::Response& res) -> void {
        const Service& service = Service::Instance();
        nlohmann::json json = nlohmann::json::parse(req.body);

        service.f_server_port.value() = json["server_port"];
        service.f_server_port.FireChanged();

        service.f_tbb_mode.value() = json["tbb_mode"];
        service.f_tbb_mode.FireChanged();

        service.f_domain.value() = json["domain"];
        service.f_domain.FireChanged();

        service.f_file_cache.value() = json["file_cache"];
        service.f_file_cache.FireChanged();

        service.f_file_cache_time.value() = json["file_cache_time"];
        service.f_file_cache_time.FireChanged();

        service.f_file_cache_max_size.value() = json["file_cache_max_size"];
        service.f_file_cache_max_size.FireChanged();

        service.f_max_requests.value() = json["f_max_requests"];
        service.f_max_requests.FireChanged();

        service.f_window_time.value() = json["f_window_time"];
        service.f_window_time.FireChanged();

        service.f_max_download_speed.value() = json["f_max_download_speed"];
        service.f_max_download_speed.FireChanged();

        config::Save();
        Service::rate_limiter.Set(service.f_max_requests, std::chrono::seconds(service.f_window_time));

        json.clear();
        json["success"] = true;
        res.set_content(json.dump(), "application/json");
    }

    auto SettingController::set_panel(const httplib::Request& req, httplib::Response& res) -> void {
        const Service& service = Service::Instance();
        nlohmann::json json = nlohmann::json::parse(req.body);

        service.f_username.value() = json["username"];
        service.f_username.FireChanged();

        service.f_password.value() = json["password"];
        service.f_password.FireChanged();

        config::Save();

        json.clear();
        json["success"] = true;
        res.set_content(json.dump(), "application/json");
    }

    auto SettingController::set_file(const httplib::Request& req, httplib::Response& res) -> void {
        const Service& service = Service::Instance();
        nlohmann::json json = nlohmann::json::parse(req.body);

        service.f_cert_path.value() = json["cert_path"].get<std::string>();
        service.f_cert_path.FireChanged();

        service.f_key_path.value() = json["key_path"].get<std::string>();
        service.f_key_path.FireChanged();

        service.f_sql_path.value() = json["sql_path"].get<std::string>();
        service.f_sql_path.FireChanged();

        service.f_web_files.value() = json["web_files"].get<std::string>();
        service.f_web_files.FireChanged();

        service.f_web_error_page.value() = json["web_error_page"].get<std::string>();
        service.f_web_error_page.FireChanged();

        service.f_files_path.value() = json["f_files_path"].get<std::string>();
        service.f_files_path.FireChanged();

        config::Save();

        json.clear();
        json["success"] = true;
        res.set_content(json.dump(), "application/json");
    }

    auto SettingController::set_log(const httplib::Request& req, httplib::Response& res) -> void {
        const Service& service = Service::Instance();
        nlohmann::json json = nlohmann::json::parse(req.body);

        service.f_log_level.value() = magic_enum::enum_cast<Logger::Level>(json["log_level"].get<std::string>()).value();
        service.f_log_level.FireChanged();

        service.f_log_type.value() = magic_enum::enum_cast<Logger::LoggerType>(json["log_type"].get<std::string>()).value();
        service.f_log_type.FireChanged();

        config::Save();

        json.clear();
        json["success"] = true;
        res.set_content(json.dump(), "application/json");
    }

    auto SettingController::set_sql(const httplib::Request& req, httplib::Response& res) -> void {
        const Service& service = Service::Instance();
        nlohmann::json json = nlohmann::json::parse(req.body);

        service.f_sqlite_max_connect.value() = json["sqlite_max_connect"];
        service.f_sqlite_max_connect.FireChanged();

        config::Save();

        json.clear();
        json["success"] = true;
        res.set_content(json.dump(), "application/json");
    }

    auto SettingController::get(const httplib::Request& req, httplib::Response& res) -> void {
        const Service& service = Service::Instance();
        nlohmann::json json;
        json["server_port"] = service.f_server_port.value();
        json["f_window_time"] = service.f_window_time.value();
        json["f_max_requests"] = service.f_max_requests.value();
        json["f_max_download_speed"] = service.f_max_download_speed.value();
        json["tbb_mode"] = service.f_tbb_mode.value();
        json["username"] = service.f_username.value();
        json["password"] = service.f_password.value();
        json["domain"] = service.f_domain.value();
        json["cert_path"] = service.f_cert_path.value();
        json["key_path"] = service.f_key_path.value();
        json["sql_path"] = service.f_sql_path.value();
        json["web_files"] = service.f_web_files.value();
        json["web_error_page"] = service.f_web_error_page.value();
        json["f_files_path"] = service.f_files_path.value();
        json["file_cache"] = service.f_file_cache.value();
        json["file_cache_time"] = service.f_file_cache_time.value();
        json["file_cache_max_size"] = service.f_file_cache_max_size.value();
        json["sqlite_max_connect"] = service.f_sqlite_max_connect.value();
        json["log_level"] = magic_enum::enum_name<Logger::Level>(service.f_log_level.value().value());
        json["log_type"] = magic_enum::enum_name<Logger::LoggerType>(service.f_log_type.value().value());
        res.set_content(json.dump(), "application/json");
    }
}
