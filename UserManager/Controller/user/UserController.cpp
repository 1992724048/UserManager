#include "UserController.h"

#include <algorithm>

#include <boost/cstdint.hpp>
#include <boost/algorithm/string/case_conv.hpp>

#include "../../Captcha.hpp"

#include "../../Dao/app/AppDao.h"
#include "../../Dao/data/DataDao.h"
#include "../../Dao/key/KeyDao.h"

#include "../../Model/KeyModel.h"

namespace controller {
    UserController::UserController() {}

    auto UserController::get_all(const httplib::Request& req, httplib::Response& res) -> void {
        nlohmann::json json = nlohmann::json::parse(req.body);

        try {
            int page = json["current_page"];
            int page_size = json["page_size"];
            json.clear();

            page = std::max(page, 1);
            if (page_size < 1 || page_size > 200) {
                throw std::runtime_error("页面显示数量过大或过小!");
            }

            const std::vector<User> users = UserDao::GetByPage(page, page_size);
            int total_users = UserDao::GetCount();

            const int total_pages = total_users > 0 ? (total_users + page_size - 1) / page_size : 0;

            json["success"] = true;
            json["message"] = "获取成功!";
            json["data"] = nlohmann::json::array();

            for (const auto& user : users) {
                json["data"].push_back({{"username", user.username}, {"is_ban", user.is_ban}, {"create_time", user.create_time}, {"password", user.password}});
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

    auto UserController::user_get(const httplib::Request& req, httplib::Response& res) -> void {
        nlohmann::json json = nlohmann::json::parse(req.body);

        try {
            const std::string username = json["username"];
            json.clear();

            if (username.empty()) {
                throw std::runtime_error("用户名不能为空!");
            }

            const auto user = UserDao::Get(username);
            if (!user) {
                throw std::runtime_error("用户不存在!");
            }

            json["success"] = true;
            json["message"] = "搜索成功!";
            json["data"] = nlohmann::json::array();
            json["data"].push_back({{"username", user->username}, {"is_ban", user->is_ban}, {"create_time", user->create_time}, {"password", user->password}});

            json["pagination"] = {{"current_page", 1}, {"total_users", 1}, {"total_pages", 1}};

            res.set_content(json.dump(), "application/json");
        } catch (std::exception& exception) {
            json.clear();
            json["success"] = false;
            json["message"] = std::string("获取用户失败!") + exception.what();
            res.set_content(json.dump(), "application/json");
        }
    }

    auto UserController::user_add(const httplib::Request& req, httplib::Response& res) -> void {
        nlohmann::json json = nlohmann::json::parse(req.body);

        try {
            const std::string username = json["username"];
            const std::string password = json["password"];
            json.clear();

            if (username.empty() || password.empty()) {
                throw std::runtime_error("用户名或密码不能为空!");
            }

            if (UserDao::Add(username, password)) {
                json["success"] = true;
                json["message"] = "添加成功!";
                res.set_content(json.dump(), "application/json");
            } else {
                throw std::runtime_error("用户可能已经存在!");
            }
        } catch (std::exception& exception) {
            json["success"] = false;
            json["message"] = std::string("添加用户失败!") + exception.what();
            res.set_content(json.dump(), "application/json");
        }
    }

    auto UserController::user_login(const httplib::Request& req, httplib::Response& res) -> void {
        nlohmann::json json = nlohmann::json::parse(req.body);

        try {
            const std::string username = json["username"];
            const std::string password = json["password"];
            std::string captcha = json["captcha"];
            const std::string app_name = json["app_name"];
            json.clear();

            if (username.empty() || password.empty()) {
                throw std::runtime_error("用户名或密码不能为空!");
            }

            boost::to_upper(captcha);
            if (captchas[req.remote_addr].second != captcha) {
                throw std::runtime_error("验证码错误!");
            }

            if (app_name.empty()) {
                throw std::runtime_error("应用名不能为空!");
            }

            const auto user = UserDao::Get(username);
            if (!user || user->password != password) {
                throw std::runtime_error("用户名或密码错误!");
            }

            if (user->is_ban) {
                throw std::runtime_error("账户已被封禁!");
            }

            const auto app = AppDao::Get(app_name);
            if (!app) {
                throw std::runtime_error("应用不存在!");
            }

            if (app->is_stop) {
                throw std::runtime_error("应用已停用!");
            }

            auto time_ = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
            const auto data = DataDao::Get(username, app_name);
            if (!data) {
                DataDao::Add(username, app_name, time_);
                throw std::runtime_error("该用户的此应用已到期!");
            }

            if (data->end_time <= time_) {
                throw std::runtime_error("该用户的此应用已到期!");
            }

            if (heartbeat.contains(username)) {
                heartbeat.erase(username);
            }

            for (auto& [fst, snd] : captchas) {
                if (std::chrono::duration_cast<std::chrono::minutes>(std::chrono::steady_clock::now() - snd.first) >= std::chrono::minutes(1)) {
                    captchas.erase(fst);
                }
            }

            for (auto& [fst, snd] : heartbeat) {
                if (std::chrono::duration_cast<std::chrono::minutes>(std::chrono::steady_clock::now() - snd.first.second) >= std::chrono::minutes(1)) {
                    heartbeat.erase(fst);
                }
            }

            auto& [fst, snd] = heartbeat[username];
            fst.second = std::chrono::steady_clock::now();
            fst.first = data->end_time;
            snd = req.remote_addr;

            json["username"] = username;
            json["success"] = true;
            json["message"] = "登录成功!";
            json["endtime"] = data->end_time;
            res.set_content(json.dump(), "application/json");
        } catch (std::exception& exception) {
            json["success"] = false;
            json["message"] = std::string("登录失败!") + exception.what();
            res.set_content(json.dump(), "application/json");
        }
    }

    auto UserController::user_use_key(const httplib::Request& req, httplib::Response& res) -> void {
        nlohmann::json json = nlohmann::json::parse(req.body);

        try {
            const std::string username = json["username"];
            const std::string password = json["password"];
            const std::string app_name = json["app_name"];
            const std::string key_name = json["key"];
            json.clear();

            if (username.empty() || password.empty()) {
                throw std::runtime_error("用户名或密码不能为空!");
            }

            if (app_name.empty()) {
                throw std::runtime_error("应用名不能为空!");
            }

            if (key_name.empty()) {
                throw std::runtime_error("密钥不能为空!");
            }

            const auto user = UserDao::Get(username);
            if (!user || user->password != password) {
                throw std::runtime_error("用户名或密码错误!");
            }

            if (user->is_ban) {
                throw std::runtime_error("账户已被封禁!");
            }

            const auto app = AppDao::Get(app_name);
            if (!app) {
                throw std::runtime_error("应用不存在!");
            }

            if (app->is_stop) {
                throw std::runtime_error("应用已停用!");
            }

            const auto key = KeyDao::Get(key_name);
            if (!key) {
                throw std::runtime_error("密钥不存在!");
            }

            if (key->is_use) {
                throw std::runtime_error("密钥已被使用!");
            }

            if (key->app_id != app_name) {
                throw std::runtime_error("密钥不属于该应用!");
            }

            int64_t ret_time = 0;
            auto time_ = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
            auto data = DataDao::Get(username, app_name);
            if (!data) {
                ret_time = time_ + key->add_time;
                DataDao::Add(username, app_name, ret_time, 1);
            } else {
                int64_t end_time = data->end_time;
                if (end_time <= time_) {
                    end_time = time_ + key->add_time;
                } else {
                    end_time += key->add_time;
                }
                data->use_count++;
                DataDao::Update(username, app_name, end_time, data->use_count);
                ret_time = end_time;
            }

            KeyDao::Update(key->key_str, true, key->price, key->add_time, key->app_id);

            auto& [fst, snd] = heartbeat[username];
            fst.first = data->end_time;

            json["success"] = true;
            json["message"] = "使用成功!";
            json["endtime"] = ret_time;
            res.set_content(json.dump(), "application/json");
        } catch (std::exception& exception) {
            json["success"] = false;
            json["message"] = std::string("使用失败!") + exception.what();
            res.set_content(json.dump(), "application/json");
        }
    }

    auto UserController::user_updata(const httplib::Request& req, httplib::Response& res) -> void {
        nlohmann::json json = nlohmann::json::parse(req.body);

        try {
            const std::string username = json["username"];
            const std::string password = json["password"];
            const int is_ban = json["is_ban"];
            json.clear();

            if (username.empty()) {
                throw std::runtime_error("用户不能为空!");
            }

            if (UserDao::Update(username, password, is_ban)) {
                json["success"] = true;
                json["message"] = "更新成功!";
                res.set_content(json.dump(), "application/json");
            } else {
                throw std::runtime_error("用户不存在或更新失败!");
            }
        } catch (std::exception& exception) {
            json["success"] = false;
            json["message"] = std::string("更新用户失败!") + exception.what();
            res.set_content(json.dump(), "application/json");
        }
    }

    auto UserController::user_delete(const httplib::Request& req, httplib::Response& res) -> void {
        nlohmann::json json = nlohmann::json::parse(req.body);

        try {
            const std::string username = json["username"];
            json.clear();

            if (username.empty()) {
                throw std::runtime_error("用户不能为空!");
            }

            if (UserDao::Delete(username)) {
                json["success"] = true;
                json["message"] = "删除成功!";
                res.set_content(json.dump(), "application/json");
            } else {
                throw std::runtime_error("用户不存在或删除失败!");
            }
        } catch (std::exception& exception) {
            json["success"] = false;
            json["message"] = std::string("删除用户失败!") + exception.what();
            res.set_content(json.dump(), "application/json");
        }
    }

    auto UserController::user_register(const httplib::Request& req, httplib::Response& res) -> void {
        nlohmann::json json = nlohmann::json::parse(req.body);

        try {
            const std::string username = json["username"];
            const std::string password = json["password"];
            const std::string captcha = json["captcha"];
            json.clear();

            if (username.empty() || password.empty()) {
                throw std::runtime_error("用户名和密码不能为空!");
            }

            if (username.size() < 8 || password.size() < 8) {
                throw std::runtime_error("用户名和密码不能小于8位!");
            }

            if (!captchas.contains(req.remote_addr)) {
                throw std::runtime_error("获取验证码数据失败!");
            }

            if (captchas[req.remote_addr].second != captcha) {
                throw std::runtime_error("验证码错误!");
            }

            if (UserDao::Get(username).has_value()) {
                throw std::runtime_error("用户已存在!");
            }

            if (!UserDao::Add(username, password)) {
                throw std::runtime_error("注册失败!");
            }

            json["success"] = true;
            json["message"] = "注册成功!";
        } catch (std::exception& exception) {
            json["success"] = false;
            json["message"] = std::string("注册用户失败!") + exception.what();
        }
        res.set_content(json.dump(), "application/json");
    }

    auto UserController::user_get_captcha(const httplib::Request& req, httplib::Response& res) -> void {
        const auto captcha = Captcha::generate_verification_code(4);

        for (auto& [fst, snd] : captchas) {
            if (std::chrono::duration_cast<std::chrono::minutes>(std::chrono::steady_clock::now() - snd.first) >= std::chrono::minutes(5)) {
                captchas.erase(fst);
            }
        }

        auto& [fst, snd] = captchas[req.remote_addr];
        fst = std::chrono::steady_clock::now();
        snd = captcha;

        const auto mat = Captcha::generate_captcha(captcha, 200, 80);
        const auto img = Captcha::mat_to_jpeg_string(mat, 80);
        res.set_content(img, "image/jpeg");
    }

    auto UserController::post_heartbeat(const httplib::Request& req, httplib::Response& res) -> void {
        nlohmann::json json = nlohmann::json::parse(req.body);

        try {
            const std::string username = json["username"];
            json.clear();

            for (auto& [fst, snd] : heartbeat) {
                if (std::chrono::duration_cast<std::chrono::minutes>(std::chrono::steady_clock::now() - snd.first.second) >= std::chrono::minutes(1)) {
                    heartbeat.erase(fst);
                }
            }

            if (username.empty()) {
                throw std::runtime_error("用户名不能为空!");
            }

            if (!heartbeat.contains(username)) {
                throw std::runtime_error("用户未登录!");
            }

            auto& [fst, snd] = heartbeat[username];
            if (snd != req.remote_addr) {
                throw std::runtime_error("IP不一致!");
            }

            const auto time_ = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
            if (fst.first <= time_) {
                throw std::runtime_error("该用户的此应用已到期!");
            }

            fst.second = std::chrono::steady_clock::now();

            json["success"] = true;
            json["message"] = "成功!";
            json["endtime"] = fst.first;
        } catch (std::exception& exception) {
            json["success"] = false;
            json["message"] = std::string("[!] ") + exception.what();
        }
        res.set_content(json.dump(), "application/json");
    }
}
