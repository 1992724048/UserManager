#pragma once

#include "../HTTPController.h"

class AdminController final : public httplib::HttpController<AdminController>{
public:
    METHOD_LIST_BEGIN
		METHOD_ADD(AdminController::cookie_check, "/admin/cookie_check", httplib::GET, httplib::ALL, "管理员", "COOKIE检查");
		METHOD_ADD(AdminController::login, "/admin/login", httplib::POST, httplib::ALL, "管理员", "登录");
		METHOD_ADD(AdminController::get_captcha, "/admin/get_captcha", httplib::GET, httplib::ALL, "管理员", "获取验证码");
    METHOD_LIST_END

	inline static std::string captcha;

    AdminController();
	static auto cookie_check(const httplib::Request& req, httplib::Response& res) -> void;
	static auto login(const httplib::Request& req, httplib::Response& res) -> void;
	static auto get_captcha(const httplib::Request& req, httplib::Response& res) -> void;
};
