#include "AppController.h"

namespace controller {
    AppController::AppController() {}

    auto AppController::get_names(const httplib::Request& req, httplib::Response& res) -> void {
        nlohmann::json json = nlohmann::json::parse(req.body);

        try {
            const std::vector<App> apps = AppDao::GetAll();

            json["success"] = true;
            json["message"] = "获取成功!";
            json["data"] = nlohmann::json::array();

            for (const auto& app : apps) {
                json["data"].push_back(app.app_name);
            }

            res.set_content(json.dump(), "application/json");
        } catch (const std::exception& exception) {
            json["success"] = false;
            json["message"] = std::string("获取应用名称失败!") + exception.what();
            res.set_content(json.dump(), "application/json");
        }
    }

    auto AppController::get_all(const httplib::Request& req, httplib::Response& res) -> void {
        nlohmann::json json = nlohmann::json::parse(req.body);

        try {
            int page = json["current_page"];
            int page_size = json["page_size"];
            json.clear();

            page = std::max(page, 1);
            if (page_size < 1 || page_size > 200) {
                throw std::runtime_error("页面显示数量过大或过小!");
            }

            const std::vector<App> apps = AppDao::GetByPage(page, page_size);
            int total_apps = AppDao::GetCount();

            const int total_pages = total_apps > 0 ? (total_apps + page_size - 1) / page_size : 0;

            json["success"] = true;
            json["message"] = "获取成功!";
            json["data"] = nlohmann::json::array();

            for (const auto& app : apps) {
                json["data"].push_back({{"app_name", app.app_name}, {"is_stop", app.is_stop}, {"create_time", app.create_time}, {"keys", app.keys}, {"users", app.users}});
            }

            json["pagination"] = {{"current_page", page}, {"page_size", page_size}, {"total_apps", total_apps}, {"total_pages", total_pages}};
            res.set_content(json.dump(), "application/json");
        } catch (const std::exception& exception) {
            json["success"] = false;
            json["message"] = std::string("获取应用失败!") + exception.what();
            res.set_content(json.dump(), "application/json");
        }
    }

    auto AppController::get_app(const httplib::Request& req, httplib::Response& res) -> void {
        nlohmann::json json = nlohmann::json::parse(req.body);

        try {
            const std::string app_name = json["app_name"];
            json.clear();

            if (app_name.empty()) {
                throw std::runtime_error("应用不能为空!");
            }

            const auto app = AppDao::Get(app_name);
            if (!app) {
                throw std::runtime_error("应用不存在!");
            }

            json["success"] = true;
            json["message"] = "搜索成功!";
            json["data"] = nlohmann::json::array();
            json["data"].push_back({{"app_name", app->app_name}, {"is_stop", app->is_stop}, {"create_time", app->create_time}, {"keys", app->keys}, {"users", app->users}});

            json["pagination"] = {{"current_page", 1}, {"total_users", 1}, {"total_pages", 1}};

            res.set_content(json.dump(), "application/json");
        } catch (std::exception& exception) {
            json["success"] = false;
            json["message"] = std::string("获取应用失败!") + exception.what();
            res.set_content(json.dump(), "application/json");
        }
    }

    auto AppController::create_app(const httplib::Request& req, httplib::Response& res) -> void {
        nlohmann::json json = nlohmann::json::parse(req.body);

        try {
            const std::string app_name = json["app_name"];
            json.clear();

            if (app_name.empty()) {
                throw std::runtime_error("应用名不能为空!");
            }

            if (AppDao::Add(app_name)) {
                json["success"] = true;
                json["message"] = "添加成功!";
                res.set_content(json.dump(), "application/json");
            } else {
                throw std::runtime_error("添加失败或应用已存在!");
            }
        } catch (std::exception& exception) {
            json["success"] = false;
            json["message"] = std::string("添加应用失败!") + exception.what();
            res.set_content(json.dump(), "application/json");
        }
    }

    auto AppController::delete_app(const httplib::Request& req, httplib::Response& res) -> void {
        nlohmann::json json = nlohmann::json::parse(req.body);

        try {
            const std::string app_name = json["app_name"];
            json.clear();

            if (app_name.empty()) {
                throw std::runtime_error("应用名不能为空!");
            }

            if (AppDao::Delete(app_name)) {
                json["success"] = true;
                json["message"] = "删除成功!";
                res.set_content(json.dump(), "application/json");
            } else {
                throw std::runtime_error("应用不存在或删除失败!");
            }
        } catch (std::exception& exception) {
            json["success"] = false;
            json["message"] = std::string("删除应用失败!") + exception.what();
            res.set_content(json.dump(), "application/json");
        }
    }

    auto AppController::update_app(const httplib::Request& req, httplib::Response& res) -> void {
        nlohmann::json json = nlohmann::json::parse(req.body);

        try {
            const std::string app_name = json["app_name"];
            const int is_stop = json["is_stop"];
            json.clear();

            if (app_name.empty()) {
                throw std::runtime_error("应用名不能为空!");
            }

            if (AppDao::Update(app_name, is_stop)) {
                json["success"] = true;
                json["message"] = "更新成功!";
                res.set_content(json.dump(), "application/json");
            } else {
                throw std::runtime_error("应用不存在或更新失败!");
            }
        } catch (std::exception& exception) {
            json["success"] = false;
            json["message"] = std::string("更新应用失败!") + exception.what();
            res.set_content(json.dump(), "application/json");
        }
    }
}
