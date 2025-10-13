#pragma once
#include <json.hpp>
#include "../../Dao/data/DataDao.h"
#include "../HTTPController.h"

namespace controller {
    class DataController final : httplib::HttpController<DataController> {
    public:
        METHOD_LIST_BEGIN
            METHOD_ADD(DataController::get_all, "/data/get_all", httplib::POST, httplib::COOKIE, "数据", "访问所有数据");
            METHOD_ADD(DataController::get_data, "/data/get_data", httplib::POST, httplib::COOKIE, "数据", "获取指定数据");
            METHOD_ADD(DataController::create_data, "/data/create_data", httplib::POST, httplib::COOKIE, "数据", "创建数据");
            METHOD_ADD(DataController::delete_data, "/data/delete_data", httplib::POST, httplib::COOKIE, "数据", "删除数据");
            METHOD_ADD(DataController::update_data, "/data/update_data", httplib::POST, httplib::COOKIE, "数据", "更新数据");
            METHOD_ADD(DataController::reset_data, "/data/reset_data", httplib::POST, httplib::COOKIE, "数据", "重置计数器");
        METHOD_LIST_END

        DataController();
        static auto get_all(const httplib::Request& req, httplib::Response& res) -> void;
        static auto get_data(const httplib::Request& req, httplib::Response& res) -> void;
        static auto create_data(const httplib::Request& req, httplib::Response& res) -> void;
        static auto delete_data(const httplib::Request& req, httplib::Response& res) -> void;
        static auto update_data(const httplib::Request& req, httplib::Response& res) -> void;
        static auto reset_data(const httplib::Request& req, httplib::Response& res) -> void;
    };
}
