#pragma once
#include <json.hpp>

#include "../HTTPController.h"

#include "../../Dao/user/UserDao.h"

namespace controller {
    class UserController final : httplib::HttpController<UserController> {
    public:
        METHOD_LIST_BEGIN
            METHOD_ADD(UserController::get_all, "/users/get_all", httplib::POST, httplib::COOKIE, "用户", "获取所有用户");
            METHOD_ADD(UserController::user_get, "/users/user_get", httplib::POST, httplib::COOKIE, "用户", "获取指定用户");
            METHOD_ADD(UserController::user_add, "/users/user_add", httplib::POST, httplib::COOKIE, "用户", "添加用户");
            METHOD_ADD(UserController::user_login, "/users/user_login", httplib::POST, httplib::ALL, "用户", "用户登录");
            METHOD_ADD(UserController::user_use_key, "/users/user_use_key", httplib::POST, httplib::ALL, "用户", "使用密钥");
            METHOD_ADD(UserController::user_updata, "/users/user_updata", httplib::POST, httplib::COOKIE, "用户", "更新用户数据");
            METHOD_ADD(UserController::user_delete, "/users/user_delete", httplib::POST, httplib::COOKIE, "用户", "删除指定用户");
            METHOD_ADD(UserController::user_register, "/users/user_register", httplib::POST, httplib::ALL, "用户", "用户注册");
            METHOD_ADD(UserController::user_get_captcha, "/users/user_get_captcha", httplib::GET, httplib::ALL, "用户", "获取验证码");
            METHOD_ADD(UserController::post_heartbeat, "/users/heartbeat", httplib::POST, httplib::ALL, "用户", "心跳包");
        METHOD_LIST_END
    private:
        // 一定要写构造方法，不然会被优化掉
        UserController();
        static auto get_all(const httplib::Request& req, httplib::Response& res) -> void;
        static auto user_get(const httplib::Request& req, httplib::Response& res) -> void;
        static auto user_add(const httplib::Request& req, httplib::Response& res) -> void;
        static auto user_login(const httplib::Request& req, httplib::Response& res) -> void;
        static auto user_use_key(const httplib::Request& req, httplib::Response& res) -> void;
        static auto user_updata(const httplib::Request& req, httplib::Response& res) -> void;
        static auto user_delete(const httplib::Request& req, httplib::Response& res) -> void;
        static auto user_register(const httplib::Request& req, httplib::Response& res) -> void;
        static auto user_get_captcha(const httplib::Request& req, httplib::Response& res) -> void;
        static auto post_heartbeat(const httplib::Request& req, httplib::Response& res) -> void;

        inline static util::SafeMap<std::string, std::pair<std::chrono::steady_clock::time_point, std::string>> captchas;
        inline static util::SafeMap<std::string, std::pair<std::pair<long long, std::chrono::steady_clock::time_point>, std::string>> heartbeat;
    };
}
