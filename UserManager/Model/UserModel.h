#pragma once
#include <string>
#include <json.hpp>

class User {
public:
    std::string username;
    std::string password;
    int is_ban;
    long long create_time;

    User() = default;

    User(std::string username, std::string password, int is_ban, long long create_time)
        : username(std::move(username)), password(std::move(password)), is_ban(is_ban), create_time(create_time) {}
};