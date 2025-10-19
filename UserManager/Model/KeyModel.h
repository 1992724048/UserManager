#pragma once
#include <string>
#include <json.hpp>

class Key {
public:
    std::string key_str;
    int is_use;
    std::string app_id;
    long long create_time;
    int add_time;
    float price;

    Key() = default;

    Key(std::string _key_str, const int _is_use, std::string _app_id, const long long _create_time, const int _add_time, const float _price) : key_str(std::move(_key_str)),
        is_use(_is_use),
        app_id(std::move(_app_id)),
        create_time(_create_time),
        add_time(_add_time),
        price(_price) {}
};

namespace nlohmann {
    inline auto to_json(json& _j, const Key& _value) -> void {
        _j = {{"key_str", _value.key_str}, {"is_use", _value.is_use}, {"app_id", _value.app_id}, {"create_time", _value.create_time}, {"add_time", _value.add_time}, {"price", _value.price}};
    }

    inline auto from_json(const json& _j, Key& _value) -> void {
        throw std::format_error("废弃");
    }
}
