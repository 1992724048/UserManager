#include "DataDao.h"

#include "../../Model/UserModel.h"
#include "../app/AppDao.h"
#include "../user/UserDao.h"

auto DataDao::Add(const std::string& username, const std::string& app_id, const int64_t end_time, int use_count_) -> int {
    if (username.empty() || app_id.empty()) {
        return 0;
    }

    if (Get(username, app_id)) {
        return 0;
    }

    Data data;
    SQLiteWrapper::SQLBuilder builder;
    const auto sql = builder.insert("datas").columns({
        "app_id",
        "username",
        "end_time",
        "create_time",
        "use_count",
    }).build();

    data.app_id = app_id;
    data.username = username;
    data.use_count = use_count_;
    data.end_time = end_time;
    data.create_time = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();

    AppDao::AddUser(app_id);

    const auto sqlite_wrapper = SQLiteWrapper::get_connect()->get_sqlite_wrapper();
    return sqlite_wrapper->execute(sql, data.app_id, data.username, data.end_time, data.create_time, data.use_count);
}

auto DataDao::Get(const std::string& username, const std::string& app_id) -> std::optional<Data> {
    if (username.empty() || app_id.empty()) {
        return std::nullopt;
    }

    SQLiteWrapper::SQLBuilder builder;
    const auto sql = builder.select({
        "*"
    }).from("datas").where("app_id = ? AND username = ?").build();

    const auto sqlite_wrapper = SQLiteWrapper::get_connect()->get_sqlite_wrapper();
    const auto stmt = sqlite_wrapper->query(sql, app_id, username);
    if (stmt.step()) {
        return bind(stmt);
    }

    return std::nullopt;
}

auto DataDao::Update(const std::string& username, const std::string& app_id, int64_t end_time, int64_t use_count_) -> int {
    if (username.empty() || app_id.empty()) {
        return 0;
    }

    SQLiteWrapper::SQLBuilder builder;
    const auto sql = builder.update("datas").set({
        "end_time",
        "use_count",
    }).where("username = ? AND app_id = ?").build();

    AppDao::Delete(app_id);

    const auto sqlite_wrapper = SQLiteWrapper::get_connect()->get_sqlite_wrapper();
    return sqlite_wrapper->execute(sql, end_time, use_count_, username, app_id);
}

auto DataDao::Delete(const std::string& username, const std::string& app_id) -> int {
    if (username.empty() || app_id.empty()) {
        return 0;
    }

    SQLiteWrapper::SQLBuilder builder;
    const auto sql = builder.del("datas").where("app_id = ? AND username = ?").build();
    const auto sqlite_wrapper = SQLiteWrapper::get_connect()->get_sqlite_wrapper();
    return sqlite_wrapper->execute(sql, app_id, username);
}

auto DataDao::UserDelete(const std::string& username) -> int {
    if (username.empty()) {
        return 0;
    }

    SQLiteWrapper::SQLBuilder builder;
    const auto sql = builder.del("datas").where("username = ?").build();
    const auto sqlite_wrapper = SQLiteWrapper::get_connect()->get_sqlite_wrapper();
    return sqlite_wrapper->execute(sql, username);
}

auto DataDao::AppDelete(const std::string& app_id) -> int {
    if (app_id.empty()) {
        return 0;
    }

    SQLiteWrapper::SQLBuilder builder;
    const auto sql = builder.del("datas").where("app_id = ?").build();
    const auto sqlite_wrapper = SQLiteWrapper::get_connect()->get_sqlite_wrapper();
    return sqlite_wrapper->execute(sql, app_id);
}

auto DataDao::Reset(const std::string& username, const std::string& app_id) -> int {
    if (username.empty() || app_id.empty()) {
        return 0;
    }

    SQLiteWrapper::SQLBuilder builder;
    const auto sql = builder.update("datas").set({
        "use_count",
    }).where("app_id = ? AND username = ?").build();

    const auto sqlite_wrapper = SQLiteWrapper::get_connect()->get_sqlite_wrapper();
    return sqlite_wrapper->execute(sql, 0, username, app_id);
}

auto DataDao::GetByPage(const int page, const int page_size) -> std::vector<Data> {
    std::vector<Data> datas;

    if (page < 1 || page_size <= 0) {
        return datas;
    }

    const int offset = (page - 1) * page_size;

    SQLiteWrapper::SQLBuilder builder;
    const auto sql = builder.select({
        "*"
    }).from("datas").limit(page_size).offset(offset).build();

    const auto sqlite_wrapper = SQLiteWrapper::get_connect()->get_sqlite_wrapper();
    const auto stmt = sqlite_wrapper->query(sql);
    while (stmt.step())
        datas.push_back(bind(stmt));
    return datas;
}

auto DataDao::GetCount() -> int {
    SQLiteWrapper::SQLBuilder builder;
    const auto sql = builder.select({}).count("*").from("datas").build();

    const auto sqlite_wrapper = SQLiteWrapper::get_connect()->get_sqlite_wrapper();
    const auto stmt = sqlite_wrapper->query(sql);
    if (stmt.step()) {
        return stmt.getInt(0);
    }

    return 0;
}

auto DataDao::bind(const SQLiteWrapper::SQLiteStatement& stmt) -> Data {
    Data data;
    data.app_id = stmt.getString(0);
    data.username = stmt.getString(1);
    data.end_time = stmt.getInt64(2);
    data.create_time = stmt.getInt64(3);
    data.use_count = stmt.getInt64(4);
    return data;
}
