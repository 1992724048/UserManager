#include "UserDao.h"

#include <variant>

#include <boost/algorithm/string/join.hpp>

#include "../Dao.h"

#include "../app/AppDao.h"

#include "../data/DataDao.h"

UserDao::UserDao() = default;

auto UserDao::Add(const std::string& usernamme, const std::string& password) -> int {
    if (Get(usernamme)) {
        return 0;
    }

    SQLiteWrapper::SQLBuilder builder;
    const auto sql = builder.insert("users").columns({
        "username",
        "password",
        "is_ban",
        "create_time"
    }).build();

    User user;
    user.is_ban = false;
    user.create_time = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    user.username = usernamme;
    user.password = password;

    const auto sqlite_wrapper = SQLiteWrapper::get_connect()->get_sqlite_wrapper();
    return sqlite_wrapper->execute(sql, user.username, user.password, user.is_ban, user.create_time);
}

auto UserDao::Get(const std::string& username) -> std::optional<User> {
    if (username.empty()) {
        return std::nullopt;
    }

    SQLiteWrapper::SQLBuilder builder;
    const auto sql = builder.select({
        "*"
    }).from("users").where("username = ?").build();

    const auto sqlite_wrapper = SQLiteWrapper::get_connect()->get_sqlite_wrapper();
    const auto stmt = sqlite_wrapper->query(sql, username);
    if (stmt.step()) {
        return bind(stmt);
    }

    return std::nullopt;
}

auto UserDao::Update(const std::string& username, const std::string& password, int is_ban) -> int {
    if (username.empty()) {
        return 0;
    }

    SQLiteWrapper::SQLBuilder builder;
    const auto sql = builder.update("users").set({
        "password",
        "is_ban"
    }).where("username = ?").build();

    const auto sqlite_wrapper = SQLiteWrapper::get_connect()->get_sqlite_wrapper();
    return sqlite_wrapper->execute(sql, password, is_ban, username);
}

auto UserDao::Delete(const std::string& username) -> int {
    if (username.empty()) {
        return 0;
    }

    DataDao::UserDelete(username);

    SQLiteWrapper::SQLBuilder builder;
    const auto sql = builder.del("users").where("username = ?").build();

    const auto sqlite_wrapper = SQLiteWrapper::get_connect()->get_sqlite_wrapper();
    return sqlite_wrapper->execute(sql, username);
}

auto UserDao::GetByPage(const int page, const int page_size) -> std::vector<User> {
    std::vector<User> users;

    if (page < 1 || page_size <= 0) {
        return users;
    }

    const int offset = (page - 1) * page_size;

    SQLiteWrapper::SQLBuilder builder;
    const auto sql = builder.select({
        "username, password, is_ban, create_time"
    }).from("users").limit(page_size).offset(offset).build();

    const auto sqlite_wrapper = SQLiteWrapper::get_connect()->get_sqlite_wrapper();
    const auto stmt = sqlite_wrapper->query(sql);
    while (stmt.step())
        users.push_back(bind(stmt));
    return users;
}

auto UserDao::GetCount() -> int {
    SQLiteWrapper::SQLBuilder builder;
    const auto sql = builder.select({}).count("*").from("users").build();

    const auto sqlite_wrapper = SQLiteWrapper::get_connect()->get_sqlite_wrapper();
    const auto stmt = sqlite_wrapper->query(sql);
    if (stmt.step()) {
        return stmt.getInt(0);
    }

    return 0;
}

auto UserDao::Filter(const std::optional<std::string>& username_part,
                     const std::optional<bool>& is_ban,
                     const std::optional<int64_t>& start_time,
                     const std::optional<int64_t>& end_time,
                     int page,
                     int page_size) -> std::vector<User> {
    std::vector<User> users;

    if (page < 1 || page_size <= 0) {
        return users;
    }
    const int offset = (page - 1) * page_size;

    SQLiteWrapper::SQLBuilder builder;
    builder.select({
        "username",
        "password",
        "is_ban",
        "create_time"
    }).from("users").limit(page_size).offset(offset);

    using param_type = std::variant<std::string, int, int64_t>;
    std::vector<param_type> bind_params;
    std::vector<std::string> conditions;

    if (username_part) {
        conditions.emplace_back("username LIKE ?");
        bind_params.emplace_back("%" + *username_part + "%");
    }

    if (is_ban) {
        conditions.emplace_back("is_ban = ?");
        bind_params.emplace_back(static_cast<int>(*is_ban));
    }

    if (start_time && end_time) {
        conditions.emplace_back("create_time BETWEEN ? AND ?");
        bind_params.emplace_back(*start_time);
        bind_params.emplace_back(*end_time);
    } else if (start_time) {
        conditions.emplace_back("create_time >= ?");
        bind_params.emplace_back(*start_time);
    } else if (end_time) {
        conditions.emplace_back("create_time <= ?");
        bind_params.emplace_back(*end_time);
    }

    if (!conditions.empty()) {
        builder.where(boost::algorithm::join(conditions, " AND "));
    }

    auto stmt = builder.prepare();
    while (stmt->step()) {
        User user;
        user.username = stmt->getString(0);
        user.password = stmt->getString(1);
        user.is_ban = stmt->getInt(2) != 0;
        user.create_time = stmt->getInt64(3);
        users.push_back(user);
    }

    return users;
}

auto UserDao::bind(const SQLiteWrapper::SQLiteStatement& stmt) -> User {
    User user;
    user.username = stmt.getString(0);
    user.password = stmt.getString(1);
    user.is_ban = stmt.getInt(2);
    user.create_time = stmt.getInt64(3);
    return user;
}
