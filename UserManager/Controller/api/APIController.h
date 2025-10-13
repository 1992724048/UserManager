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
    template<>
    struct adl_serializer<APIParams> {
        static auto to_json(json& j, const APIParams& p) -> void {
            j = json{{"name", p.name}, {"type", p.type}, {"required", p.required}, {"desc", p.desc}};
        }

        static auto from_json(const json& j, APIParams& p) -> void {
            j.at("name").get_to(p.name);
            j.at("type").get_to(p.type);
            j.at("required").get_to(p.required);
            j.at("desc").get_to(p.desc);
        }
    };

    template<>
    struct adl_serializer<APIData> {
        static auto to_json(json& j, const APIData& d) -> void {
            j = json{{"name", d.name}, {"note", d.note}, {"url", d.url}, {"method", d.method}, {"type", d.type}, {"desc", d.desc}, {"params", d.params}};
        }

        static auto from_json(const json& j, APIData& d) -> void {
            j.at("name").get_to(d.name);
            j.at("note").get_to(d.note);
            j.at("url").get_to(d.url);
            j.at("method").get_to(d.method);
            j.at("type").get_to(d.type);
            j.at("desc").get_to(d.desc);
            j.at("params").get_to(d.params);
        }
    };
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
