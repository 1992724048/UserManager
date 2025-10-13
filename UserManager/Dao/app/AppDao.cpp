#include "AppDao.h"

#include "../data/DataDao.h"

#include "../key/KeyDao.h"

auto AppDao::Get(const std::string& app) -> std::optional<App> {
    if (app.empty()) {
        return std::nullopt;
    }

    SQLiteWrapper::SQLBuilder builder;

    const auto sql = builder.select({
        "*"
    }).from("apps").where("app_name = ?").build();

    const auto sqlite_wrapper = SQLiteWrapper::get_connect()->get_sqlite_wrapper();
    const auto stmt = sqlite_wrapper->query(sql, app);
    if (stmt.step()) {
        return bind(stmt);
    }

    return std::nullopt;
}

auto AppDao::Delete(const std::string& app) -> int {
    if (app.empty()) {
        return 0;
    }

    KeyDao::AppDelete(app);
    DataDao::AppDelete(app);

    SQLiteWrapper::SQLBuilder builder;
    const auto sql = builder.del("apps").where("app_name = ?").build();

    const auto sqlite_wrapper = SQLiteWrapper::get_connect()->get_sqlite_wrapper();
    return sqlite_wrapper->execute(sql, app);
}

auto AppDao::Update(const std::string& app, bool is_stop) -> int {
    if (app.empty()) {
        return 0;
    }

    SQLiteWrapper::SQLBuilder builder;
    const auto sql = builder.update("apps").set({
        "is_stop",
    }).where("app_name = ?").build();

    const auto sqlite_wrapper = SQLiteWrapper::get_connect()->get_sqlite_wrapper();
    return sqlite_wrapper->execute(sql, is_stop, app);
}

auto AppDao::Update(const std::string& app, int users, int keys) -> int {
    if (app.empty()) {
        return 0;
    }

    SQLiteWrapper::SQLBuilder builder;
    const auto sql = builder.update("apps").set({
        "users",
        "keys"
    }).where("app_name = ?").build();

    const auto sqlite_wrapper = SQLiteWrapper::get_connect()->get_sqlite_wrapper();
    return sqlite_wrapper->execute(sql, users, keys, app);
}

auto AppDao::Add(const std::string& app_name) -> int {
    if (Get(app_name)) {
        return 0;
    }

    App app;

    SQLiteWrapper::SQLBuilder builder;
    const auto sql = builder.insert("apps").columns({
        "app_name",
        "create_time",
        "users",
        "is_stop",
        "keys"
    }).build();

    app.app_name = app_name;
    app.create_time = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    app.users = 0;
    app.is_stop = false;
    app.keys = 0;

    const auto sqlite_wrapper = SQLiteWrapper::get_connect()->get_sqlite_wrapper();
    return sqlite_wrapper->execute(sql, app.app_name, app.create_time, app.users, app.is_stop, app.keys);
}

auto AppDao::SubKey(const std::string& app_name) -> int {
    auto app = Get(app_name);
    if (!app) {
        return 0;
    }

    return Update(app_name, app->users, --app->keys);
}

auto AppDao::AddKey(const std::string& app_name) -> int {
    auto app = Get(app_name);
    if (!app) {
        return 0;
    }

    return Update(app_name, app->users, ++app->keys);
}

auto AppDao::SubUser(const std::string& app_name) -> int {
    auto app = Get(app_name);
    if (!app) {
        return 0;
    }

    return Update(app_name, --app->users, app->keys);
}

auto AppDao::AddUser(const std::string& app_name) -> int {
    auto app = Get(app_name);
    if (!app) {
        return 0;
    }

    return Update(app_name, ++app->users, app->keys);
}

auto AppDao::GetByPage(const int page, const int page_size) -> std::vector<App> {
    std::vector<App> apps;

    if (page < 1 || page_size <= 0) {
        return apps;
    }

    const int offset = (page - 1) * page_size;

    SQLiteWrapper::SQLBuilder builder;
    const auto sql = builder.select({
        "*"
    }).from("apps").limit(page_size).offset(offset).build();

    const auto sqlite_wrapper = SQLiteWrapper::get_connect()->get_sqlite_wrapper();
    const auto stmt = sqlite_wrapper->query(sql);
    while (stmt.step())
        apps.push_back(bind(stmt));
    return apps;
}

auto AppDao::GetCount() -> int {
    SQLiteWrapper::SQLBuilder builder;
    const auto sql = builder.select({}).count("*").from("apps").build();

    const auto sqlite_wrapper = SQLiteWrapper::get_connect()->get_sqlite_wrapper();
    const auto stmt = sqlite_wrapper->query(sql);
    if (stmt.step()) {
        return stmt.getInt(0);
    }

    return 0;
}

auto AppDao::bind(const SQLiteWrapper::SQLiteStatement& stmt) -> App {
    App app_;
    app_.app_name = stmt.getString(0);
    app_.create_time = stmt.getInt64(1);
    app_.users = stmt.getInt(2);
    app_.is_stop = stmt.getInt(3);
    app_.keys = stmt.getInt(4);
    return app_;
}
