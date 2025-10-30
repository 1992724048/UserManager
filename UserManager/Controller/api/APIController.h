#pragma once

#include "../HTTPController.h"

struct APIParams {
    std::string name;
    std::string type;
    bool required;
    std::string desc;
};

struct APIData {
    std::string name;
    std::string note;
    std::string url;
    std::string method;
    int type;
    std::string desc;
    std::vector<APIParams> params;
};

namespace nlohmann {
    inline auto to_json(json& _j, const APIParams& _p) -> void {
        _j = json{{"name", _p.name}, {"type", _p.type}, {"required", _p.required}, {"desc", _p.desc}};
    }

    inline auto from_json(const json& _j, APIParams& _p) -> void {
        _j.at("name").get_to(_p.name);
        _j.at("type").get_to(_p.type);
        _j.at("required").get_to(_p.required);
        _j.at("desc").get_to(_p.desc);
    }

    inline auto to_json(json& _j, const APIData& _d) -> void {
        _j = json{{"name", _d.name}, {"note", _d.note}, {"url", _d.url}, {"method", _d.method}, {"type", _d.type}, {"desc", _d.desc}, {"params", _d.params}};
    }

    inline auto from_json(const json& _j, APIData& _d) -> void {
        _j.at("name").get_to(_d.name);
        _j.at("note").get_to(_d.note);
        _j.at("url").get_to(_d.url);
        _j.at("method").get_to(_d.method);
        _j.at("type").get_to(_d.type);
        _j.at("desc").get_to(_d.desc);
        _j.at("params").get_to(_d.params);
    }
}

class APIController final : public httplib::HttpController<APIController> {
public:
    METHOD_LIST_BEGIN
        METHOD_ADD(APIController::timestamp, "/api/timestamp", httplib::GET, httplib::ALL, "API", "服务器时间戳");
        METHOD_ADD(APIController::ip, "/api/ip", httplib::GET, httplib::ALL, "API", "获取访问者IP");
        METHOD_ADD(APIController::info, "/api/info", httplib::GET, httplib::COOKIE, "API", "获取系统信息");
        METHOD_ADD(APIController::get_all, "/api/get_all", httplib::GET, httplib::COOKIE, "API", "获取所有接口");
        METHOD_ADD(APIController::set_api, "/api/set_api", httplib::POST, httplib::COOKIE, "API", "设置接口");
        METHOD_ADD(APIController::get_doc, "/api/get_doc", httplib::POST, httplib::COOKIE, "API", "获取接口文档");
        METHOD_ADD(APIController::command, "/api/command", httplib::POST, httplib::COOKIE, "API", "运行PowerShell命令");
        METHOD_ADD(APIController::check, "/api/check", httplib::GET, httplib::COOKIE, "API", "检查风险选项");
    METHOD_LIST_END

    APIController();
    static auto timestamp(const httplib::Request& req, httplib::Response& res) -> void;
    static auto ip(const httplib::Request& req, httplib::Response& res) -> void;
    static auto info(const httplib::Request& req, httplib::Response& res) -> void;
    static auto get_all(const httplib::Request& req, httplib::Response& res) -> void;
    static auto set_api(const httplib::Request& req, httplib::Response& res) -> void;
    static auto get_doc(const httplib::Request& req, httplib::Response& res) -> void;
    static auto command(const httplib::Request& req, httplib::Response& res) -> void;
    static auto check(const httplib::Request& req, httplib::Response& res) -> void;

    inline static util::SafeMap<std::string, APIData> apis;
};
