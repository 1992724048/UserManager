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

    App() = default;

    App(std::string app_name, const long long create_time, const int users, const int is_stop, const int keys)
        : app_name(std::move(app_name)), create_time(create_time), users(users), keys(keys), is_stop(is_stop) {}
};