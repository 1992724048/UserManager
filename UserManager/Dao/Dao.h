#pragma once
#include "../Service.h"
#include <sqlite3.h>
#include <string>
#include <stdexcept>
#include <type_traits>
#include <string_view>
#include <functional>
#include <utility>
#include <variant>

class SQLiteWrapper {
public:
    class SQLiteStatement {
    public:
        SQLiteStatement(sqlite3_stmt* stmt) : stmt(stmt) {}

        ~SQLiteStatement() {
            if (stmt) {
                sqlite3_finalize(stmt);
            }
        }

        [[nodiscard]] auto step() const -> bool {
            const int rc = sqlite3_step(stmt);
            if (rc == SQLITE_ROW) {
                return true;
            }
            if (rc == SQLITE_DONE) {
                return false;
            }
            throw std::runtime_error("SQL step error: " + std::string(sqlite3_errmsg(sqlite3_db_handle(stmt))));
        }

        [[nodiscard]] auto getInt(const int column) const -> int {
            return sqlite3_column_int(stmt, column);
        }

        [[nodiscard]] auto getInt64(const int column) const -> int64_t {
            return sqlite3_column_int64(stmt, column);
        }

        [[nodiscard]] auto getString(const int column) const -> std::string {
            return reinterpret_cast<const char*>(sqlite3_column_text(stmt, column));
        }

        [[nodiscard]] auto getDouble(const int column) const -> double {
            return sqlite3_column_double(stmt, column);
        }

        auto bind(const int index, const std::string& value) const -> void {
            if (sqlite3_bind_text(stmt, index, value.c_str(), -1, SQLITE_TRANSIENT) != SQLITE_OK) {
                throw std::runtime_error("Failed to bind string parameter");
            }
        }

        auto bind(const int index, const int value) const -> void {
            if (sqlite3_bind_int(stmt, index, value) != SQLITE_OK) {
                throw std::runtime_error("Failed to bind int parameter");
            }
        }

        auto bind(const int index, const int64_t value) const -> void {
            if (sqlite3_bind_int64(stmt, index, value) != SQLITE_OK) {
                throw std::runtime_error("Failed to bind int64 parameter");
            }
        }

        auto bind(const int index, const float value) const -> void {
            bind(index, static_cast<double>(value));
        }

        auto bind(const int index, const double value) const -> void {
            if (sqlite3_bind_double(stmt, index, value) != SQLITE_OK) {
                throw std::runtime_error("Failed to bind double parameter");
            }
        }

        auto bind(const int index, const bool value) const -> void {
            bind(index, static_cast<int>(value));
        }

        SQLiteStatement(const SQLiteStatement&) = delete;
        auto operator=(const SQLiteStatement&) -> SQLiteStatement& = delete;

    private:
        sqlite3_stmt* stmt;
    };

    class SQLBuilder {
        using ParamVariant = std::variant<std::string, int, int64_t, bool, float, double>;

    public:
        auto insert(const std::string& table) -> SQLBuilder& {
            operation = "INSERT";
            this->table = table;
            return *this;
        }

        auto update(const std::string& table) -> SQLBuilder& {
            operation = "UPDATE";
            this->table = table;
            return *this;
        }

        auto select(const std::initializer_list<std::string> cols) -> SQLBuilder& {
            operation = "SELECT";
            this->cols.assign(cols.begin(), cols.end());
            return *this;
        }

        auto del(const std::string& table) -> SQLBuilder& {
            operation = "DELETE";
            this->table = table;
            return *this;
        }

        auto columns(const std::initializer_list<std::string> cols) -> SQLBuilder& {
            this->cols = cols;
            return *this;
        }

        auto set(const std::initializer_list<std::string> setters) -> SQLBuilder& {
            for (const auto& s : setters) {
                this->setters.push_back(s + " = ?");
            }
            return *this;
        }

        auto where(const std::string& condition) -> SQLBuilder& {
            this->condition = "WHERE " + condition;
            return *this;
        }

        auto from(const std::string& table) -> SQLBuilder& {
            this->table = table;
            return *this;
        }

        auto limit(const int limit) -> SQLBuilder& {
            if (limit < 0) {
                throw std::invalid_argument("LIMIT cannot be negative");
            }
            this->limit_ = limit;
            return *this;
        }

        auto offset(const int offset) -> SQLBuilder& {
            if (offset < 0) {
                throw std::invalid_argument("OFFSET cannot be negative");
            }
            this->offset_ = offset;
            return *this;
        }

        auto count(const std::string& column) -> SQLBuilder& {
            this->cols.clear();
            this->cols.push_back("COUNT(" + column + ")");
            return *this;
        }

        [[nodiscard]] auto build() const -> std::string {
            if (operation == "INSERT") {
                return buildInsert();
            }
            if (operation == "UPDATE") {
                return buildUpdate();
            }
            if (operation == "SELECT") {
                return buildSelect();
            }
            if (operation == "DELETE") {
                return buildDelete();
            }
            throw std::runtime_error("Unsupported SQL operation");
        }

        template<typename T>
        auto bind(const T& value) -> SQLBuilder& {
            params_.emplace_back(value);
            return *this;
        }

        template<typename... Args>
        auto bind_params(const Args&... args) -> SQLBuilder& {
            (params_.emplace_back(args), ...);
            return *this;
        }

        auto prepare() -> std::shared_ptr<SQLiteStatement> {
            const auto sql = build();
            auto stmt = get_connect()->get_sqlite_wrapper()->prepare(sql);

            for (size_t i = 0; i < params_.size(); ++i) {
                const auto index = i + 1;
                std::visit([&stmt, index]<typename T0>(T0&& arg) {
                               using T = std::decay_t<T0>;
                               if constexpr (std::is_same_v<T, std::string>) {
                                   stmt->bind(index, arg);
                               } else if constexpr (std::is_same_v<T, int>) {
                                   stmt->bind(index, arg);
                               } else if constexpr (std::is_same_v<T, int64_t>) {
                                   stmt->bind(index, arg);
                               } else if constexpr (std::is_same_v<T, bool>) {
                                   stmt->bind(index, static_cast<int>(arg));
                               } else if constexpr (std::is_same_v<T, float>) {
                                   stmt->bind(index, static_cast<double>(arg));
                               } else if constexpr (std::is_same_v<T, double>) {
                                   stmt->bind(index, arg);
                               }
                           },
                           params_[i]);
            }

            return stmt;
        }

        auto where(const std::string& condition, auto&&... args) -> SQLBuilder& {
            this->condition = "WHERE " + condition;
            (params_.emplace_back(std::forward<decltype(args)>(args)), ...);
            return *this;
        }

        auto set(const std::vector<std::pair<std::string, ParamVariant>>& setters_) -> SQLBuilder& {
            for (const auto& [col, val] : setters_) {
                setters.push_back(col + " = ?");
                params_.push_back(val);
            }
            return *this;
        }

    private:
        std::string operation;
        std::string table;
        std::vector<std::string> cols;
        std::vector<std::string> setters;
        std::string condition;
        std::vector<ParamVariant> params_;
        int limit_ = -1;
        int offset_ = -1;

        [[nodiscard]] auto buildInsert() const -> std::string {
            std::string sql = "INSERT INTO " + table;
            sql += " (" + join(cols) + ")";
            sql += " VALUES (" + generatePlaceholders(cols.size()) + ")";
            return sql;
        }

        [[nodiscard]] auto buildUpdate() const -> std::string {
            std::string sql = "UPDATE " + table;
            sql += " SET " + join(setters);
            if (!condition.empty()) {
                sql += " " + condition;
            }
            return sql;
        }

        [[nodiscard]] auto buildSelect() const -> std::string {
            // 处理空列情况（SELECT *）
            const std::string columns = cols.empty() ? "*" : join(cols);
            std::string sql = "SELECT " + columns;
            sql += " FROM " + table;
            if (!condition.empty()) {
                sql += " " + condition;
            }
            if (limit_ != -1) {
                sql += " LIMIT " + std::to_string(limit_);
            }
            if (offset_ != -1) {
                sql += " OFFSET " + std::to_string(offset_);
            }
            return sql;
        }

        [[nodiscard]] auto buildDelete() const -> std::string {
            std::string sql = "DELETE FROM " + table;
            if (!condition.empty()) {
                sql += " " + condition;
            }
            return sql;
        }

        static auto join(const std::vector<std::string>& items) -> std::string {
            std::string result;
            for (size_t i = 0; i < items.size(); ++i) {
                if (i > 0) {
                    result += ", ";
                }
                result += items[i];
            }
            return result;
        }

        static auto generatePlaceholders(const size_t count) -> std::string {
            std::string placeholders;
            for (size_t i = 0; i < count; ++i) {
                if (i > 0) {
                    placeholders += ", ";
                }
                placeholders += "?";
            }
            return placeholders;
        }
    };


    SQLiteWrapper() {
        if (sqlite3_open(Service::Instance().f_sql_path.value().string().data(), &db) != SQLITE_OK) {
            throw std::runtime_error("无法打开数据库");
        }

        if (sqlite3_exec(db, "PRAGMA journal_mode=WAL;", nullptr, nullptr, nullptr) != SQLITE_OK) {
            throw std::runtime_error("无法设置WAL模式");
        }
    }

    SQLiteWrapper(const std::string& db_path) {
        if (sqlite3_open(db_path.c_str(), &db) != SQLITE_OK) {
            throw std::runtime_error("无法打开数据库");
        }

        if (sqlite3_exec(db, "PRAGMA journal_mode=WAL;", nullptr, nullptr, nullptr) != SQLITE_OK) {
            throw std::runtime_error("无法设置WAL模式");
        }
    }

    ~SQLiteWrapper() {
        if (db) {
            sqlite3_close(db);
        }
    }

    [[nodiscard]] auto execute(const std::string& query) const -> int {
        char* errMsg = nullptr;
        if (sqlite3_exec(db, query.c_str(), nullptr, nullptr, &errMsg) != SQLITE_OK) {
            const std::string error_msg = errMsg;
            sqlite3_free(errMsg);
            throw std::runtime_error("SQLite执行错误: " + error_msg);
        }
        return sqlite3_changes(db);
    }

    auto execute(const std::string& query, int (*callback)(void*, int, char**, char**), void* data = nullptr) const -> int {
        char* errMsg = nullptr;
        if (sqlite3_exec(db, query.c_str(), callback, data, &errMsg) != SQLITE_OK) {
            const std::string error_msg = errMsg;
            sqlite3_free(errMsg);
            throw std::runtime_error("SQLite执行错误: " + error_msg);
        }
        return sqlite3_changes(db);
    }

    auto execute(const std::string& query, std::function<int(void*, int, char**, char**)> callback, void* data = nullptr) const -> int {
        char* errMsg = nullptr;
        auto callback_wrapper = [](void* data, const int argc, char** argv, char** colName) -> int {
            const auto* func = static_cast<std::function<int(void*, int, char**, char**)>*>(data);
            return (*func)(nullptr, argc, argv, colName);
        };
        if (sqlite3_exec(db, query.c_str(), callback_wrapper, &callback, &errMsg) != SQLITE_OK) {
            const std::string error_msg = errMsg;
            sqlite3_free(errMsg);
            throw std::runtime_error("SQLite执行错误: " + error_msg);
        }
        return sqlite3_changes(db);
    }

    [[nodiscard]] auto query(const std::string& query) const -> SQLiteStatement {
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
            throw std::runtime_error("SQLite准备语句失败");
        }
        return {stmt};
    }

    template<typename... Args>
    auto query(const std::string& query, Args&&... args) -> SQLiteStatement {
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db, query.data(), -1, &stmt, nullptr) != SQLITE_OK) {
            throw std::runtime_error("SQLite准备语句失败");
        }

        int index = 1;
        (bind_parameter(stmt, index++, std::forward<Args>(args)), ...);

        return {stmt};
    }

    template<typename... Args>
    auto execute(const std::string& query, Args&&... args) -> int {
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db, query.data(), -1, &stmt, nullptr) != SQLITE_OK) {
            throw std::runtime_error("SQLite准备语句失败");
        }

        int index = 1;
        (bind_parameter(stmt, index++, std::forward<Args>(args)), ...);

        if (sqlite3_step(stmt) != SQLITE_DONE) {
            sqlite3_finalize(stmt);
            throw std::runtime_error("SQLite执行错误");
        }

        const int changes = sqlite3_changes(db);
        sqlite3_finalize(stmt);
        return changes;
    }

    [[nodiscard]] auto prepare(const std::string& sql) const -> std::shared_ptr<SQLiteStatement> {
        sqlite3_stmt* stmt = nullptr;
        const int rc = sqlite3_prepare_v2(db, sql.data(), -1, &stmt, nullptr);

        if (rc != SQLITE_OK) {
            const char* errMsg = sqlite3_errmsg(db);
            throw std::runtime_error("SQL prepare error: " + std::string(errMsg));
        }

        return std::make_shared<SQLiteStatement>(stmt);
    }

    class Connection {
        std::shared_ptr<SQLiteWrapper> sqlite_wrapper;

    public:
        explicit Connection(const std::shared_ptr<SQLiteWrapper>& wrapper) {
            sqlite_wrapper = wrapper;
        }

        ~Connection() {
            connection_queue.push(std::move(sqlite_wrapper));
            condition.notify_one();
        }

        auto get_sqlite_wrapper() -> std::shared_ptr<SQLiteWrapper> {
            return sqlite_wrapper;
        }
    };

    static auto get_connect() -> std::shared_ptr<Connection> {
        std::shared_ptr<SQLiteWrapper> wrapper;
        if (!connection_queue.try_pop(wrapper)) {
            std::unique_lock lock(connection_mutex);
            condition.wait(lock,
                           [] {
                               return !connection_queue.empty();
                           });
        }
        return util::make_mi_malloc_shared<Connection>(wrapper);
    }

    static auto initializePool() -> void {
        const auto max = Service::Instance().f_sqlite_max_connect.value();
        for (int i = 0; std::cmp_less(i, max); ++i) {
            connection_queue.push(std::make_shared<SQLiteWrapper>());
        }
    }

private:
    sqlite3* db = nullptr;
    inline static tbb::concurrent_queue<std::shared_ptr<SQLiteWrapper>> connection_queue;
    inline static std::mutex connection_mutex;
    inline static std::condition_variable condition;

    template<typename T>
    auto bind_parameter(sqlite3_stmt* stmt, int index, T&& value) -> void {
        using Type = std::decay_t<T>;
        if constexpr (std::is_integral_v<Type>) {
            sqlite3_bind_int64(stmt, index, static_cast<sqlite3_int64>(value));
        } else if constexpr (std::is_floating_point_v<Type>) {
            sqlite3_bind_double(stmt, index, value);
        } else if constexpr (std::is_constructible_v<std::string_view, Type>) {
            const std::string_view str = value;
            sqlite3_bind_text(stmt, index, str.data(), str.size(), SQLITE_TRANSIENT);
        } else if constexpr (std::is_same_v<Type, std::nullptr_t>) {
            sqlite3_bind_null(stmt, index);
        } else if constexpr (std::is_same_v<Type, std::string>) {
            const std::string str = value;
            sqlite3_bind_text(stmt, index, str.data(), str.size(), SQLITE_TRANSIENT);
        } else {
            static_assert(sizeof(T) == 0, "不支持参数!");
        }
    }
};

class Dao {
public:
    static auto init_date_base() -> void {
        // 启用sqlite优化选项
        sqlite3_config(SQLITE_CONFIG_MULTITHREAD);
        bool new_db = false;
        const auto& ser = Service::Instance();
        LOG_DEBUG << "数据库路径: " << ser.f_sql_path.value().string();
        const auto db_path = ser.f_sql_path.value().parent_path();

        if (!is_directory(db_path)) {
            LOG_INFO << "文件夹未找到! 准备创建文件夹.";
            if (!create_directories(db_path)) {
                throw std::runtime_error("无法创建数据库文件夹");
            }
            new_db = true;
        }

        SQLiteWrapper db_wrapper(ser.f_sql_path.value().string());

        if (new_db) {
            const std::vector<std::string> sql_statements = {
                R"(create table apps
                    (
                        app_name    TEXT              not null,
                        create_time BIGINT  default 0 not null,
                        users       INTEGER default 0 not null,
                        is_stop     INTEGER default 0 not null,
                        keys        INTEGER           not null
                    );
                    )",
                R"(create table datas
                    (
                        app_id      TEXT            not null,
                        username    TEXT default '' not null,
                        end_time    BIGINT          not null,
                        create_time BIGINT          not null,
                        use_count   BIGINT          not null
                    );
                    )",
                R"(create table keys
                    (
                        key_str     TEXT              not null,
                        is_use      TINYINT           not null,
                        app_id      TEXT   default '' not null,
                        create_time BIGINT default 0  not null,
                        add_time    INTEGER           not null,
                        price       REAL              not null
                    );

                    create index key
                        on keys (key_str);

                    )",
                R"(create table users
                    (
                        username    TEXT    not null,
                        password    TEXT    not null,
                        is_ban      INTEGER not null,
                        create_time BIGINT  not null
                    );

                    create index username
                        on users (username);

                    )",
            };

            for (const auto& sql : sql_statements) {
                db_wrapper.execute(sql);
            }
        }

        SQLiteWrapper::initializePool();
    }
};
