#pragma once
#include "../Dao.h"
#include "../../Model/KeyModel.h"

class KeyDao : public Dao {
public:
    KeyDao() = default;
    static auto Get(const std::string& key) -> std::optional<Key>;
    static auto Delete(const std::string& key) -> int;
    static auto AppDelete(const std::string& app) -> int;
    static auto Update(const std::string& key, int is_use, int price, int add_time, const std::string& app_id) -> int;
    static auto Add(float price, int add_time, const std::string& app_id, int count) -> int;
    static auto ClearUse() -> int;
    static auto GetUseKeys() -> std::vector<Key>;
    static auto GetByPage(int page, int page_size = 50) -> std::vector<Key>;
    static auto GetCount() -> int;
private:
    static auto bind(const SQLiteWrapper::SQLiteStatement& stmt) -> Key;
};