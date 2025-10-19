#pragma once
#include <string>
#include <json.hpp>

class User {
public:
    std::string username;
    std::string password;
    int is_ban;
    long long create_time;
    bool online;

    User() = default;

    User(std::string _username, std::string _password, const int _is_ban, const long long _create_time) : username(std::move(_username)),
                                                                                          password(std::move(_password)),
                                                                                          is_ban(_is_ban),
                                                                                          create_time(_create_time),
                                                                                          online{false} {}
};

namespace nlohmann {
    inline auto to_json(json& _j, const User& _user) -> void {
        _j = { {"username", _user.username}, {"is_ban", _user.is_ban}, {"create_time", _user.create_time}, {"password", _user.password}, {"online", _user.online} };
    }

    inline auto from_json(const json& _j, User& _value) -> void {
        throw std::format_error("废弃");
    }
}
