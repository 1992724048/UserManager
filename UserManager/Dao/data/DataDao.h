#pragma once
#include "../Dao.h"
#include "../../Model/DataModel.h"

class DataDao : public Dao {
public:
    DataDao() = default;
    static auto Add(const std::string& username, const std::string& app_id, int64_t end_time = 0, int use_count_ = 0) -> int;
    static auto Get(const std::string& username, const std::string& app_id) -> std::optional<Data>;
    static auto Update(const std::string& username, const std::string& app_id, int64_t end_time, int64_t use_count_) -> int;
    static auto Delete(const std::string& username, const std::string& app_id) -> int;
    static auto UserDelete(const std::string& username) -> int;
    static auto AppDelete(const std::string& app_id) -> int;
    static auto Reset(const std::string& username, const std::string& app_id) -> int;
    static auto GetByPage(int page, int page_size = 50) -> std::vector<Data>;
    static auto GetCount() -> int;
private:
    static auto bind(const SQLiteWrapper::SQLiteStatement& stmt) -> Data;
};