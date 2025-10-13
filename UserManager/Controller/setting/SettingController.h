#pragma once

#include "../HTTPController.h"

namespace controller {
	class SettingController final : httplib::HttpController<SettingController>  {
	public:
		METHOD_LIST_BEGIN
            METHOD_ADD(SettingController::set_server, "/setting/set_server", httplib::POST, httplib::COOKIE, "设置", "服务器设置");
            METHOD_ADD(SettingController::set_panel, "/setting/set_panel", httplib::POST, httplib::COOKIE, "设置", "面板设置");
            METHOD_ADD(SettingController::set_file, "/setting/set_file", httplib::POST, httplib::COOKIE, "设置", "文件设置");
            METHOD_ADD(SettingController::set_log, "/setting/set_log", httplib::POST, httplib::COOKIE, "设置", "日志设置");
            METHOD_ADD(SettingController::set_sql, "/setting/set_sql", httplib::POST, httplib::COOKIE, "设置", "数据库设置");
            METHOD_ADD(SettingController::get, "/setting/get", httplib::GET, httplib::COOKIE, "设置", "获取所有设置");
        METHOD_LIST_END

		SettingController();
		static auto set_server(const httplib::Request& req, httplib::Response& res) -> void;
		static auto set_panel(const httplib::Request& req, httplib::Response& res) -> void;
		static auto set_file(const httplib::Request& req, httplib::Response& res) -> void;
		static auto set_log(const httplib::Request& req, httplib::Response& res) -> void;
		static auto set_sql(const httplib::Request& req, httplib::Response& res) -> void;
        static auto get(const httplib::Request& req, httplib::Response& res) -> void;
	};
}
