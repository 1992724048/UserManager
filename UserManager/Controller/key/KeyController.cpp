#include "KeyController.h"

namespace controller {
    KeyController::KeyController() {}

    auto KeyController::get_all(const httplib::Request& req, httplib::Response& res) -> void {
        nlohmann::json json = nlohmann::json::parse(req.body);

        try {
            int page = json["current_page"];
            int page_size = json["page_size"];
            json.clear();

            page = std::max(page, 1);
            if (page_size < 1 || page_size > 200) {
                throw std::runtime_error("页面显示数量过大或过小!");
            }

            const std::vector<Key> keys = KeyDao::GetByPage(page, page_size);
            int total_keys = KeyDao::GetCount();

            const int total_pages = total_keys > 0 ? (total_keys + page_size - 1) / page_size : 0;

            json["success"] = true;
            json["message"] = "获取成功!";
            json["data"] = nlohmann::json::array();

            for (const auto& key : keys) {
                json["data"].push_back({{"key", key.key_str}, {"is_use", key.is_use}, {"create_time", key.create_time}, {"app_id", key.app_id}, {"add_time", key.add_time}, {"price", key.price}});
            }

            json["pagination"] = {{"current_page", page}, {"page_size", page_size}, {"total_keys", total_keys}, {"total_pages", total_pages}};
            res.set_content(json.dump(), "application/json");
        } catch (const std::exception& exception) {
            json["success"] = false;
            json["message"] = std::string("获取密钥失败!") + exception.what();
            res.set_content(json.dump(), "application/json");
        }
    }

    auto KeyController::get_key(const httplib::Request& req, httplib::Response& res) -> void {
        nlohmann::json json = nlohmann::json::parse(req.body);

        try {
            const std::string key = json["search_key"];
            json.clear();

            if (key.empty()) {
                throw std::runtime_error("密钥不能为空!");
            }

            const auto key_ = KeyDao::Get(key);
            if (!key_) {
                throw std::runtime_error("密钥不存在!");
            }

            json["success"] = true;
            json["message"] = "搜索成功!";
            json["data"] = nlohmann::json::array();
            json["data"].push_back({
                {"key", key_->key_str},
                {"is_use", key_->is_use},
                {"create_time", key_->create_time},
                {"app_id", key_->app_id},
                {"add_time", key_->add_time},
                {"price", key_->price}
            });

            json["pagination"] = {{"current_page", 1}, {"total_users", 1}, {"total_pages", 1}};

            res.set_content(json.dump(), "application/json");
        } catch (std::exception& exception) {
            json["success"] = false;
            json["message"] = std::string("获取密钥失败!") + exception.what();
            res.set_content(json.dump(), "application/json");
        }
    }

    auto KeyController::create_key(const httplib::Request& req, httplib::Response& res) -> void {
        nlohmann::json json = nlohmann::json::parse(req.body);

        try {
            const std::string app_id = json["app_id"];
            const int add_time = json["add_time"];
            const float price = json["price"];
            const int count = json["count"];
            json.clear();

            if (app_id.empty()) {
                throw std::runtime_error("应用不能为空!");
            }

            if (!count || !add_time) {
                throw std::runtime_error("数量和增加时间不能为0!");
            }

            if (KeyDao::Add(price, add_time, app_id, count) == count) {
                json["success"] = true;
                json["message"] = "添加成功!";
                res.set_content(json.dump(), "application/json");
            } else {
                throw std::runtime_error("应用不存在/添加失败/仅部分添加成功!");
            }
        } catch (std::exception& exception) {
            json["success"] = false;
            json["message"] = std::string("添加密钥失败!") + exception.what();
            res.set_content(json.dump(), "application/json");
        }
    }

    auto KeyController::delete_key(const httplib::Request& req, httplib::Response& res) -> void {
        nlohmann::json json = nlohmann::json::parse(req.body);

        try {
            std::string key_ = json["key"];
            json.clear();

            if (key_.empty()) {
                throw std::runtime_error("密钥不能为空!");
            }

            if (KeyDao::Delete(key_)) {
                json["success"] = true;
                json["message"] = "删除成功!";
                res.set_content(json.dump(), "application/json");
            } else {
                throw std::runtime_error("密钥不存在或删除失败!");
            }
        } catch (std::exception& exception) {
            json["success"] = false;
            json["message"] = std::string("删除密钥失败!") + exception.what();
            res.set_content(json.dump(), "application/json");
        }
    }

    auto KeyController::update_key(const httplib::Request& req, httplib::Response& res) -> void {
        nlohmann::json json = nlohmann::json::parse(req.body);

        try {
            const std::string key = json["key"];
            const int is_use = json["is_use"];
            const std::string app_id = json["app_id"];
            const int add_time = json["add_time"];
            const float price = json["price"];
            json.clear();

            if (key.empty()) {
                throw std::runtime_error("密钥不能为空!");
            }

            if (app_id.empty()) {
                throw std::runtime_error("应用不能为空!");
            }

            if (!add_time) {
                throw std::runtime_error("增加时间不能为0!");
            }

            if (KeyDao::Update(key, is_use, price, add_time, app_id)) {
                json["success"] = true;
                json["message"] = "更新成功!";
                res.set_content(json.dump(), "application/json");
            } else {
                throw std::runtime_error("密钥不存在/应用不存在/更新失败!");
            }
        } catch (std::exception& exception) {
            json["success"] = false;
            json["message"] = std::string("更新密钥失败!") + exception.what();
            res.set_content(json.dump(), "application/json");
        }
    }

    auto KeyController::clear_use(const httplib::Request& req, httplib::Response& res) -> void {
        nlohmann::json json;

        try {
            if (KeyDao::ClearUse()) {
                json["success"] = true;
                json["message"] = "清除成功!";
                res.set_content(json.dump(), "application/json");
            } else {
                throw std::runtime_error("!");
            }
        } catch (std::exception& exception) {
            json["success"] = false;
            json["message"] = std::string("清除失败") + exception.what();
            res.set_content(json.dump(), "application/json");
        }
    }

    auto KeyController::calc(const httplib::Request& req, httplib::Response& res) -> void {
        nlohmann::json json;
        json["data"] = nlohmann::json::array();
        try {
            const auto keys = KeyDao::GetUseKeys();
            if (keys.empty()) {
                throw std::runtime_error("没有被使用的密钥!");
            }

            std::map<std::string, std::pair<float, int>> value;
            for (const Key& key : keys) {
                auto& [val1, val2] = value[key.app_id];
                val1 += key.price;
                val2++;
            }

            for (const auto& [fst, snd] : value) {
                json["data"].push_back({{"app_name", fst}, {"price_summary", snd.first}, {"sales_quantity", snd.second}});
            }

            json["success"] = true;
            json["message"] = "获取成功!";
            res.set_content(json.dump(), "application/json");
        } catch (std::exception& exception) {
            json["success"] = false;
            json["message"] = std::string("获取失败!") + exception.what();
            res.set_content(json.dump(), "application/json");
        }
    }
}
