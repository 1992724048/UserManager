#include "KeyDao.h"

#include "../app/AppDao.h"

auto KeyDao::Get(const std::string& key) -> std::optional<Key> {
    if (key.empty()) {
        return std::nullopt;
    }

    SQLiteWrapper::SQLBuilder builder;

    const auto sql = builder.select({"*"}).from("keys").where("key_str = ?").build();

    const auto sqlite_wrapper = SQLiteWrapper::get_connect()->get_sqlite_wrapper();
    const auto stmt = sqlite_wrapper->query(sql, key);
    if (stmt.step()) {
        return bind(stmt);
    }

    return std::nullopt;
}

auto KeyDao::Delete(const std::string& key) -> int {
    if (key.empty()) {
        return 0;
    }

    auto key_ = Get(key);
    if (!key_) {
        return 0;
    }

    SQLiteWrapper::SQLBuilder builder;
    const auto sql = builder.del("keys").where("key_str = ?").build();

    const auto sqlite_wrapper = SQLiteWrapper::get_connect()->get_sqlite_wrapper();
    if (sqlite_wrapper->execute(sql, key)) {
        return AppDao::SubKey(key_->app_id);
    }
    return 0;
}

auto KeyDao::AppDelete(const std::string& app) -> int {
    if (app.empty()) {
        return 0;
    }

    SQLiteWrapper::SQLBuilder builder;
    const auto sql = builder.del("keys").where("app_id = ?").build();

    const auto sqlite_wrapper = SQLiteWrapper::get_connect()->get_sqlite_wrapper();
    return sqlite_wrapper->execute(sql, app);
}

auto KeyDao::Update(const std::string& key, int is_use, int price, int add_time, const std::string& app_id) -> int {
    if (key.empty()) {
        return 0;
    }

    auto key_ = Get(key);
    if (!key_) {
        return 0;
    }

    if (key_->is_use == is_use && key_->price == price && key_->add_time == add_time && key_->app_id == app_id) {
        return 0;
    }

    if (!AppDao::Get(app_id)) {
        return 0;
    }

    if (key_->app_id != app_id) {
        AppDao::SubKey(key_->app_id);
        AppDao::AddKey(app_id);
    }

    SQLiteWrapper::SQLBuilder builder;
    const auto sql = builder.update("keys").set({"is_use", "price", "add_time", "app_id"}).where("key_str = ?").build();

    const auto sqlite_wrapper = SQLiteWrapper::get_connect()->get_sqlite_wrapper();
    return sqlite_wrapper->execute(sql, is_use, price, add_time, app_id, key);
}

auto KeyDao::Add(float price, int add_time, const std::string& app_id, int count) -> int {
    if (!count || !add_time) {
        return 0;
    }

    if (!AppDao::Get(app_id)) {
        return 0;
    }

    Key key;

    SQLiteWrapper::SQLBuilder builder;
    const auto sql = builder.insert("keys").columns({"key_str", "is_use", "app_id", "create_time", "add_time", "price"}).build();

    key.add_time = add_time;
    key.app_id = app_id;
    key.is_use = false;
    key.price = price;

    const auto sqlite_wrapper = SQLiteWrapper::get_connect()->get_sqlite_wrapper();

    int count_{0};
    for (int i = 0; i < count; ++i) {
        key.key_str = util::generate_timestamp_sha256();
        key.create_time = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
        if (sqlite_wrapper->execute(sql, key.key_str, key.is_use, key.app_id, key.create_time, key.add_time, key.price)) {
            AppDao::AddKey(app_id);
            count_++;
        }
    }

    return count_;
}

auto KeyDao::ClearUse() -> int {
    SQLiteWrapper::SQLBuilder builder;
    const auto sql = builder.select({"*"}).from("keys").where("is_use = ?").build();

    int num{};
    const auto sqlite_wrapper = SQLiteWrapper::get_connect()->get_sqlite_wrapper();
    const auto stmt = sqlite_wrapper->query(sql, 1);
    while (stmt.step()) {
        num += Delete(bind(stmt).key_str);
    }
    return num;
}

auto KeyDao::GetUseKeys() -> std::vector<Key> {
    SQLiteWrapper::SQLBuilder builder;
    const auto sql = builder.select({"*"}).from("keys").where("is_use = ?").build();

    std::vector<Key> keys;
    const auto sqlite_wrapper = SQLiteWrapper::get_connect()->get_sqlite_wrapper();
    const auto stmt = sqlite_wrapper->query(sql, 1);
    while (stmt.step()) {
        keys.push_back(bind(stmt));
    }
    return keys;
}

auto KeyDao::GetByPage(const int page, const int page_size, const std::string& app) -> std::vector<Key> {
    std::vector<Key> keys;

    if (page < 1 || page_size <= 0) {
        return keys;
    }

    const int offset = (page - 1) * page_size;

    SQLiteWrapper::SQLBuilder builder;
    const auto sql = app.empty()
                         ? builder.select({"*"}).from("keys").limit(page_size).offset(offset).build()
                         : builder.select({"*"}).from("keys").where("app_id = ?").limit(page_size).offset(offset).build();

    const auto sqlite_wrapper = SQLiteWrapper::get_connect()->get_sqlite_wrapper();
    const auto stmt = app.empty() ? sqlite_wrapper->query(sql) : sqlite_wrapper->query(sql, app);
    while (stmt.step()) {
        keys.push_back(bind(stmt));
    }
    return keys;
}

auto KeyDao::GetCount() -> int {
    SQLiteWrapper::SQLBuilder builder;
    const auto sql = builder.select({}).count("*").from("keys").build();

    const auto sqlite_wrapper = SQLiteWrapper::get_connect()->get_sqlite_wrapper();
    const auto stmt = sqlite_wrapper->query(sql);
    if (stmt.step()) {
        return stmt.getInt(0);
    }

    return 0;
}

auto KeyDao::bind(const SQLiteWrapper::SQLiteStatement& stmt) -> Key {
    Key key;
    key.key_str = stmt.getString(0);
    key.is_use = stmt.getInt(1);
    key.app_id = stmt.getString(2);
    key.create_time = stmt.getInt64(3);
    key.add_time = stmt.getInt(4);
    key.price = stmt.getDouble(5);
    return key;
}
