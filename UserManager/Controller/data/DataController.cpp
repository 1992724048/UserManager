#include "DataController.h"

namespace controller {
    DataController::DataController() {}

    auto DataController::get_all(const httplib::Request& req, httplib::Response& res) -> void {
        nlohmann::json json = nlohmann::json::parse(req.body);

        try {
            int page = json["current_page"];
            int page_size = json["page_size"];
            json.clear();

            page = std::max(page, 1);
            if (page_size < 1 || page_size > 200) {
                throw std::runtime_error("页面显示数量过大或过小!");
            }

            const std::vector<Data> datas = DataDao::GetByPage(page, page_size);
            int total_users = DataDao::GetCount();

            const int total_pages = total_users > 0 ? (total_users + page_size - 1) / page_size : 0;

            json["success"] = true;
            json["message"] = "获取成功!";
            json["data"] = nlohmann::json::array();

            for (const auto& data : datas) {
                json["data"].push_back({{"username", data.username}, {"app_id", data.app_id}, {"create_time", data.create_time}, {"end_time", data.end_time}, {"use_count", data.use_count}});
            }

            json["pagination"] = {{"current_page", page}, {"page_size", page_size}, {"total_users", total_users}, {"total_pages", total_pages}};

            res.set_content(json.dump(), "application/json");
        } catch (std::exception& exception) {
            json.clear();
            json["success"] = false;
            json["message"] = std::string("获取失败!") + exception.what();
            res.set_content(json.dump(), "application/json");
        }
    }

    auto DataController::get_data(const httplib::Request& req, httplib::Response& res) -> void {
        nlohmann::json json = nlohmann::json::parse(req.body);

        try {
            const std::string username = json["username"];
            const std::string app_id = json["app_id"];
            json.clear();

            if (username.empty() || app_id.empty()) {
                throw std::runtime_error("应用或用户不能为空!");
            }

            const auto app = DataDao::Get(username, app_id);
            if (!app) {
                throw std::runtime_error("数据不存在!");
            }

            json["success"] = true;
            json["message"] = "搜索成功!";
            json["data"] = nlohmann::json::array();
            json["data"].push_back({{"username", app->username}, {"app_id", app->app_id}, {"create_time", app->create_time}, {"end_time", app->end_time}, {"use_count", app->use_count}});

            json["pagination"] = {{"current_page", 1}, {"total_users", 1}, {"total_pages", 1}};

            res.set_content(json.dump(), "application/json");
        } catch (std::exception& exception) {
            json["success"] = false;
            json["message"] = std::string("获取数据失败!") + exception.what();
            res.set_content(json.dump(), "application/json");
        }
    }

    auto DataController::create_data(const httplib::Request& req, httplib::Response& res) -> void {
        nlohmann::json json = nlohmann::json::parse(req.body);

        try {
            const std::string username = json["username"];
            const std::string app_id = json["app_id"];
            json.clear();

            if (username.empty() || app_id.empty()) {
                throw std::runtime_error("应用或用户不能为空!");
            }

            if (DataDao::Add(username, app_id)) {
                json["success"] = true;
                json["message"] = "添加成功!";
                res.set_content(json.dump(), "application/json");
            } else {
                throw std::runtime_error("添加失败或数据已存在!");
            }
        } catch (std::exception& exception) {
            json["success"] = false;
            json["message"] = std::string("添加数据失败!") + exception.what();
            res.set_content(json.dump(), "application/json");
        }
    }

    auto DataController::delete_data(const httplib::Request& req, httplib::Response& res) -> void {
        nlohmann::json json = nlohmann::json::parse(req.body);

        try {
            const std::string username = json["username"];
            const std::string app_id = json["app_id"];
            json.clear();

            if (username.empty() || app_id.empty()) {
                throw std::runtime_error("应用或用户不能为空!");
            }

            if (DataDao::Delete(username, app_id)) {
                json["success"] = true;
                json["message"] = "删除成功!";
                res.set_content(json.dump(), "application/json");
            } else {
                throw std::runtime_error("数据不存在或删除失败!");
            }
        } catch (std::exception& exception) {
            json["success"] = false;
            json["message"] = std::string("删除数据失败!") + exception.what();
            res.set_content(json.dump(), "application/json");
        }
    }

    auto DataController::update_data(const httplib::Request& req, httplib::Response& res) -> void {
        nlohmann::json json = nlohmann::json::parse(req.body);

        try {
            const std::string username = json["username"];
            const std::string app_id = json["app_id"];
            const int64_t end_time = json["end_time"];
            json.clear();

            if (username.empty() || app_id.empty()) {
                throw std::runtime_error("应用或用户不能为空!");
            }

            const auto data = DataDao::Get(username, app_id);
            if (data && DataDao::Update(username, app_id, end_time, data->use_count)) {
                json["success"] = true;
                json["message"] = "更新成功!";
                res.set_content(json.dump(), "application/json");
            } else {
                throw std::runtime_error("数据不存在或更新失败!");
            }
        } catch (std::exception& exception) {
            json["success"] = false;
            json["message"] = std::string("更新数据失败!") + exception.what();
            res.set_content(json.dump(), "application/json");
        }
    }

    auto DataController::reset_data(const httplib::Request& req, httplib::Response& res) -> void {
        nlohmann::json json = nlohmann::json::parse(req.body);

        try {
            const std::string username = json["username"];
            const std::string app_id = json["app_id"];
            json.clear();

            if (username.empty() || app_id.empty()) {
                throw std::runtime_error("应用或用户不能为空!");
            }

            if (DataDao::Reset(username, app_id)) {
                json["success"] = true;
                json["message"] = "重置成功!";
                res.set_content(json.dump(), "application/json");
            } else {
                throw std::runtime_error("数据不存在或重置失败!");
            }
        } catch (std::exception& exception) {
            json["success"] = false;
            json["message"] = std::string("重置数据失败!") + exception.what();
            res.set_content(json.dump(), "application/json");
        }
    }
}
