#pragma once
#include <json.hpp>
#include "../../Dao/app/AppDao.h"
#include "../HTTPController.h"

namespace controller {
    class AppController final : httplib::HttpController<AppController> {
    public:
        METHOD_LIST_BEGIN
            METHOD_ADD(AppController::get_names, "/app/get_names", httplib::GET, httplib::COOKIE, "应用", "访问所有应用名称");
            METHOD_ADD(AppController::get_all, "/app/get_all", httplib::POST, httplib::COOKIE, "应用", "访问所有应用");
            METHOD_ADD(AppController::get_app, "/app/get_app", httplib::POST, httplib::COOKIE, "应用", "获取指定应用");
            METHOD_ADD(AppController::create_app, "/app/create_app", httplib::POST, httplib::COOKIE, "应用", "创建应用");
            METHOD_ADD(AppController::delete_app, "/app/delete_app", httplib::POST, httplib::COOKIE, "应用", "删除应用");
            METHOD_ADD(AppController::update_app, "/app/update_app", httplib::POST, httplib::COOKIE, "应用", "更新应用");
            METHOD_ADD(AppController::get_ver, "/app/get_ver", httplib::POST, httplib::ALL, "应用", "获取应用版本号");
        METHOD_LIST_END

        AppController();
        static auto get_names(const httplib::Request& req, httplib::Response& res) -> void;
        static auto get_all(const httplib::Request& req, httplib::Response& res) -> void;
        static auto get_app(const httplib::Request& req, httplib::Response& res) -> void;
        static auto create_app(const httplib::Request& req, httplib::Response& res) -> void;
        static auto delete_app(const httplib::Request& req, httplib::Response& res) -> void;
        static auto update_app(const httplib::Request& req, httplib::Response& res) -> void;
        static auto get_ver(const httplib::Request& req, httplib::Response& res) -> void;

    };
}
