#pragma once
#include "../Dao.h"
#include "../../Model/UserModel.h"

class UserDao {
public:
    UserDao();
    static auto Add(const std::string& username, const std::string& password) -> int;
    static auto Get(const std::string& username) -> std::optional<User>;
    static auto Update(const std::string& username, const std::string& password, int is_ban) -> int;
    static auto Delete(const std::string& username) -> int;
    static auto GetByPage(int page, int page_size = 50) -> std::vector<User>;
    static auto GetCount() -> int;
    static auto Filter(const std::optional<std::string>& username_part,
                       const std::optional<bool>& is_ban,
                       const std::optional<int64_t>& start_time,
                       const std::optional<int64_t>& end_time,
                       int page,
                       int page_size) -> std::vector<User>;
private:
    static auto bind(const SQLiteWrapper::SQLiteStatement& stmt) -> User;
};