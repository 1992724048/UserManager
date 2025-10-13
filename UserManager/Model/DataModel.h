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

    Data(std::string app_id, std::string username, const long long end_time, const int use_count, const long long create_time)
        : app_id(std::move(app_id)), username(std::move(username)), end_time(end_time), create_time(create_time), use_count(use_count) {}
};