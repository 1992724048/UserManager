#pragma once
#include <string>
#include <json.hpp>

class Data {
public:
    std::string app_id;
    std::string username;
    long long end_time;
    long long create_time;
    long long use_count;

    Data() = default;

    Data(std::string _app_id, std::string _username, const long long _end_time, const int _use_count, const long long _create_time) : app_id(std::move(_app_id)),
        username(std::move(_username)),
        end_time(_end_time),
        create_time(_create_time),
        use_count(_use_count) {}
};

namespace nlohmann {
    inline auto to_json(json& _j, const Data& _value) -> void {
        _j = {{"app_id", _value.app_id}, {"username", _value.username}, {"end_time", _value.end_time}, {"create_time", _value.create_time}, {"use_count", _value.use_count}};
    }

    inline auto from_json(const json& _j, Data& _value) -> void {
        throw std::format_error("废弃");
    }
}
