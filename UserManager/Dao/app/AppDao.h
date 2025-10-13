#pragma once
#include "../Dao.h"
#include "../../Model/AppModel.h"

class AppDao : public Dao {
public:
    AppDao() = default;
    static auto Get(const std::string& app) -> std::optional<App>;
    static auto Delete(const std::string& app) -> int;
    static auto Update(const std::string& app, bool is_stop) -> int;
    static auto Update(const std::string& _app, int _users, int _keys) -> int;
    static auto Add(const std::string& app_name) -> int;
    static auto SubKey(const std::string& app_name) -> int;
    static auto AddKey(const std::string& app_name) -> int;
    static auto SubUser(const std::string& app_name) -> int;
    static auto AddUser(const std::string& app_name) -> int;
    static auto GetByPage(int page, int page_size = 50) -> std::vector<App>;
    static auto GetCount() -> int;
private:
    static auto bind(const SQLiteWrapper::SQLiteStatement& stmt) -> App;
};