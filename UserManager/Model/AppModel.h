#pragma once
#include <string>
#include <json.hpp>

class App {
public:
    std::string app_name;
    long long create_time;
    int users;
    int keys;
    int is_stop;
    std::string ver;

    App() = default;

    App(std::string _app_name, const long long _create_time, const int _users, const int _is_stop, const int _keys, std::string _ver) : app_name(std::move(_app_name)),
        create_time(_create_time),
        users(_users),
        keys(_keys),
        is_stop(_is_stop),
        ver(std::move(_ver)) {}
};

namespace nlohmann {
    inline auto to_json(json& _j, const App& _value) -> void {
        _j = {{"app_name", _value.app_name}, {"create_time", _value.create_time}, {"users", _value.users}, {"keys", _value.keys}, {"is_stop", _value.is_stop}, {"app_ver", _value.ver}};
    }

    inline auto from_json(const json& _j, App& _value) -> void {
        throw std::format_error("废弃");
    }
}
