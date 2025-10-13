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

    Key(std::string key_str, const int is_use, std::string app_id, const long long create_time, const int add_time, const float price)
        : key_str(std::move(key_str)), is_use(is_use), app_id(std::move(app_id)), create_time(create_time), add_time(add_time), price(price) {}
};