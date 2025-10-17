#include "AdminController.h"

#include <boost/algorithm/string.hpp>

#include "../../Captcha.hpp"

AdminController::AdminController() {
}

auto AdminController::cookie_check(const httplib::Request& req, httplib::Response& res) -> void {
    nlohmann::json json;
    if (Service::check_cookie_valid(req)) {
        json["success"] = true;
        res.set_content(json.dump(), "application/json");
        return;
    }
    json["success"] = false;
    res.set_content(json.dump(), "application/json");
}

auto AdminController::login(const httplib::Request& req, httplib::Response& res) -> void {
    const Service& service = Service::Instance();
    nlohmann::json json = nlohmann::json::parse(req.body);
    const std::string username_ = json["username"];
    const std::string password_ = json["password"];
    std::string captcha_ = json["captcha"];

    json.clear();

    boost::to_upper(captcha_);
    if (captcha_ != captcha) {
        LOG_CRIT << fmt::format("{}:{} 管理员登录失败: 验证码错误", req.remote_addr, req.remote_port);
        json["message"] = "验证码错误";
        json["success"] = false;
        res.set_content(json.dump(), "application/json");
        return;
    }

    if (username_ == service.f_username.value() && password_ == service.f_password.value()) {
        LOG_CRIT << fmt::format("{}:{} 管理员登录成功!", req.remote_addr, req.remote_port);
        res.set_header("Set-Cookie", Service::add_cookie());
        json["message"] = "验证完成";
        json["success"] = true;
    } else {
        LOG_CRIT << fmt::format("{}:{} 管理员登录失败: 用户名或密码错误", req.remote_addr, req.remote_port);
        json["message"] = "用户名或密码错误";
        json["success"] = false;
    }

    res.set_content(json.dump(), "application/json");
}

auto AdminController::get_captcha(const httplib::Request& req, httplib::Response& res) -> void {
    captcha = Captcha::generate_verification_code(4);
    const auto mat = Captcha::generate_captcha(captcha, 200, 80);
    const auto img = Captcha::mat_to_jpeg_string(mat, 80);
    res.set_content(img, "image/jpeg");
}
