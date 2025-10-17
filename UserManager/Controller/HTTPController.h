#pragma once
#include "../Service.h"
#undef DELETE

#define METHOD_LIST_BEGIN \
    static void initPathRouting() {
#define METHOD_ADD(method, pattern, ...) \
        registerMethod(&method, pattern, __VA_ARGS__, #method)
#define METHOD_LIST_END \
        return; \
    }

namespace httplib {
    enum HttpRequestType {
        GET,
        POST,
        DELETE,
        PUT
    };

    enum HttpRequest { ALL, COOKIE, NOACCESS };

    class HttpControllerBase {
    protected:
        ~HttpControllerBase() = default;

    public:
        struct ControllerData {
            std::string url_path;
            std::string note;
            std::string group;
            HttpRequestType request_type;
            HttpRequest request;
            HttpControllerBase* this_ptr;
            std::function<void(const Request&, Response&)> call_back;
        };

        static auto registerHandler(const std::string& class_name, const ControllerData& data) -> void {
            controllers[class_name] = data;
            controllers_default[class_name] = data;
        }

        static auto registerMethod() -> void {
            const Service& instance = Service::Instance();
            std::ifstream file(util::app_path() / "url.json", std::ios::in);
            if (file) {
                file >> api_json;
                file.close();
            }

            for (auto& [name, controller] : controllers) {
                if (api_json.contains(name)) {
                    controller.request = api_json[name];
                } else {
                    api_json[name] = controller.request;
                }

                auto lambda = [&](const Request& req, Response& res) {
                    if (controller.request == NOACCESS) {
                        LOG_CRIT << fmt::format("{}:{} 访问禁止访问资源!", req.remote_addr, req.remote_port);
                        res.status = 403;
                        return;
                    }

                    if (controller.request == COOKIE && !Service::check_cookie_valid(req)) {
                        LOG_CRIT << fmt::format("{}:{} 未经授权的访问!", req.remote_addr, req.remote_port);
                        res.status = 401;
                        return;
                    }

                    controller.call_back(req, res);
                };

                switch (controller.request_type) {
                    case GET:
                        instance.server->Get(controller.url_path, lambda);
                        break;
                    case POST:
                        instance.server->Post(controller.url_path, lambda);
                        break;
                    case DELETE:
                        instance.server->Delete(controller.url_path, lambda);
                        break;
                    case PUT:
                        instance.server->Put(controller.url_path, lambda);
                        break;
                }
            }

            std::ofstream file_out(util::app_path() / "url.json", std::ios::out);
            file_out << api_json;
            file_out.close();
        }

        static auto save(HttpRequest type, const std::string& name) -> void {
            if (api_json.contains(name)) {
                api_json[name] = type;
                controllers[name].request = type;
            }

            std::ofstream file_out(util::app_path() / "url.json", std::ios::out);
            file_out << api_json;
            file_out.close();
        }

        inline static nlohmann::json api_json;
        inline static util::SafeMap<std::string, ControllerData> controllers;
        inline static util::SafeMap<std::string, ControllerData> controllers_default;
    };

    template<typename T, bool AutoCreation = true>
    class HttpController : public HttpControllerBase {
    public:
        static constexpr bool isAutoCreation = AutoCreation;

    protected:
        ~HttpController() = default;

        static auto registerMethod(void (T::*function)(const Request&, Response&),
                                   const std::string& pattern,
                                   const HttpRequestType request_type,
                                   const HttpRequest request,
                                   const std::string& group,
                                   const std::string& note,
                                   const std::string& handler_name) -> void {
            const ControllerData data(pattern, note, group, request_type, request, this_, std::bind(function, &this_, std::placeholders::_1));
            registerHandler(handler_name, data);
        }

        static auto registerMethod(void (*function)(const Request&, Response&),
                                   const std::string& pattern,
                                   const HttpRequestType request_type,
                                   const HttpRequest request,
                                   const std::string& group,
                                   const std::string& note,
                                   const std::string& handlerName) -> void {
            const ControllerData data(pattern, note, group, request_type, request, nullptr, function);
            registerHandler(handlerName, data);
        }

    private:
        class methodRegistrator {
        public:
            methodRegistrator() {
                if (AutoCreation) {
                    T::initPathRouting();
                }
            }
        };

        static methodRegistrator registrator_;
        static HttpController<T> this_;

        virtual auto touch() -> void* {
            return &registrator_;
        }
    };

    template<typename T, bool AutoCreation>
    typename HttpController<T, AutoCreation>::methodRegistrator HttpController<T, AutoCreation>::registrator_;
}
