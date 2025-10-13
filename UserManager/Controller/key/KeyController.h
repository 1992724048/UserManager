#pragma once
#include <json.hpp>
#include "../../Dao/key/KeyDao.h"
#include "../HTTPController.h"

namespace controller {
    class KeyController final : httplib::HttpController<KeyController> {
    public:
        METHOD_LIST_BEGIN
            METHOD_ADD(KeyController::get_all, "/key/get_all", httplib::POST, httplib::COOKIE, "密钥", "获取所有密钥");
            METHOD_ADD(KeyController::get_key, "/key/get_key", httplib::POST, httplib::COOKIE, "密钥", "获取指定密钥");
            METHOD_ADD(KeyController::create_key, "/key/create_key", httplib::POST, httplib::COOKIE, "密钥", "创建密钥");
            METHOD_ADD(KeyController::delete_key, "/key/delete_key", httplib::POST, httplib::COOKIE, "密钥", "删除密钥");
            METHOD_ADD(KeyController::update_key, "/key/update_key", httplib::POST, httplib::COOKIE, "密钥", "更新密钥");
            METHOD_ADD(KeyController::clear_use, "/key/clear_use", httplib::POST, httplib::COOKIE, "密钥", "清除已用");
            METHOD_ADD(KeyController::calc, "/key/calc", httplib::GET, httplib::COOKIE, "密钥", "计算收入");
        METHOD_LIST_END

        KeyController();
        static auto get_all(const httplib::Request& req, httplib::Response& res) -> void;
        static auto get_key(const httplib::Request& req, httplib::Response& res) -> void;
        static auto create_key(const httplib::Request& req, httplib::Response& res) -> void;
        static auto delete_key(const httplib::Request& req, httplib::Response& res) -> void;
        static auto update_key(const httplib::Request& req, httplib::Response& res) -> void;
        static auto clear_use(const httplib::Request& req, httplib::Response& res) -> void;
        static auto calc(const httplib::Request& req, httplib::Response& res) -> void;
    };
}
