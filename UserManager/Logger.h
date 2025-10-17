#pragma once
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <iostream>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <mutex>
#include <chrono>
#include <iomanip>
#include <format>
#include <string_view>
#include <windows.h>

class Logger {
public:
    enum class Level { None, Critical, Error, Warning, Info, Debug, Trace };

    enum class LoggerType { Any, ConsoleLogger, FileLogger };

    static auto set_level(const Level _level, const LoggerType _type = LoggerType::Any) -> void {
        std::scoped_lock lock(m_mutex_);
        switch (_type) {
        case LoggerType::Any:
            s_console_log_level_ = _level;
            s_file_log_level_ = _level;
            break;
        case LoggerType::ConsoleLogger:
            s_console_log_level_ = _level;
            break;
        case LoggerType::FileLogger:
            s_file_log_level_ = _level;
            break;
        }
    }

    static auto get_level(const LoggerType _type) -> Level {
        std::scoped_lock lock(m_mutex_);
        switch (_type) {
        case LoggerType::Any:
            return s_file_log_level_ < s_console_log_level_ ? s_file_log_level_ : s_console_log_level_;
        case LoggerType::ConsoleLogger:
            return s_console_log_level_;
        case LoggerType::FileLogger:
            return s_file_log_level_;
        }
        return Level::None;
    }

    static auto prepare_file_logging(const std::filesystem::path& _dir) -> void {
        std::scoped_lock lock(m_mutex_);
        s_directory_ = _dir;
        if (!is_directory(_dir)) {
            create_directories(_dir);
        }
        const auto now = std::chrono::system_clock::now();
        s_log_file_path_ = std::format("{}/log_{}.txt", _dir.string(), now.time_since_epoch().count());
    }

    class LogMessage {
    public:
        LogMessage(const Level _level, const std::string_view _file, const int _line) : m_level_(_level), m_file_(_file), m_line_(_line) {}

        ~LogMessage() {
            commit();
        }

        template<typename T>
        auto operator<<(const T& _value) -> LogMessage& {
            m_stream_ << _value;
            return *this;
        }

        auto operator<<(std::ostream& (*_manip)(std::ostream&)) -> LogMessage& {
            m_stream_ << _manip;
            return *this;
        }

    private:
        auto commit() -> void {
            log(m_level_, std::string(m_file_), m_line_, m_stream_.str());
        }

        Level m_level_;
        std::string m_file_;
        int m_line_;
        std::ostringstream m_stream_;
    };

    static auto open_console() -> void {
        if (!AttachConsole(ATTACH_PARENT_PROCESS)) {
            AllocConsole();
        }

        FILE* fp_out_;
        freopen_s(&fp_out_, "CONOUT$", "w", stdout);
        freopen_s(&fp_out_, "CONOUT$", "w", stderr);
        freopen_s(&fp_out_, "CONIN$", "r", stdin);
        _wfreopen_s(&fp_out_, L"CONOUT$", L"w", stdout);
        _wfreopen_s(&fp_out_, L"CONOUT$", L"w", stderr);
        _wfreopen_s(&fp_out_, L"CONIN$", L"r", stdin);

        SetConsoleOutputCP(65001);
        SetConsoleCP(65001);

        SetConsoleTitleA("日志");

        setvbuf(stdout, nullptr, _IONBF, 0);
        setvbuf(stderr, nullptr, _IONBF, 0);

        std::ios::sync_with_stdio(false);
        std::cout.setf(std::ios::unitbuf);
        std::cerr.setf(std::ios::unitbuf);
    }

    static auto log(Level _level, const std::string& _file, int _line, const std::string& _msg) -> void {
        bool log_to_console = (s_console_log_level_ != Level::None && s_console_log_level_ >= _level);
        bool log_to_file = (s_file_log_level_ != Level::None && s_file_log_level_ >= _level);

        std::filesystem::path p(_file);
        std::string filename = p.filename().string();

        auto t = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
        tm tm_time;
        gmtime_s(&tm_time, &t);
        std::ostringstream time_stream;
        time_stream << std::setw(2) << std::setfill('0') << tm_time.tm_hour << ":" << std::setw(2) << std::setfill('0') << tm_time.tm_min << ":" << std::setw(2) << std::setfill('0') << tm_time.tm_sec;

        static const auto k_start_time = std::chrono::steady_clock::now();
        auto now = std::chrono::steady_clock::now();
        std::chrono::duration<double> elapsed = now - k_start_time;
        std::ostringstream runtime_stream;
        runtime_stream << std::fixed << std::setprecision(3) << elapsed.count() << "s";

        const char* level_text = get_level_text(_level);

        std::lock_guard lock(m_mutex_);
        if (log_to_console) {
            WORD color;
            switch (_level) {
            case Level::Critical:
                color = FOREGROUND_RED | FOREGROUND_INTENSITY;
                break;
            case Level::Error:
                color = FOREGROUND_RED;
                break;
            case Level::Warning:
                color = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY;
                break;
            case Level::Info:
                color = FOREGROUND_GREEN;
                break;
            case Level::Debug:
                color = FOREGROUND_BLUE | FOREGROUND_GREEN;
                break;
            case Level::Trace:
                color = FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY;
                break;
            default:
                color = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
                break;
            case Level::None:
                break;
            }

            set_console_color(color);
            std::cout << "[" << level_text << "] ";
            set_console_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
            std::cout << "[" << runtime_stream.str() << "] ";
            std::cout << "[T:" << std::to_string(GetCurrentThreadId()) << "] ";
            set_console_color(FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
            std::cout << "[" << filename << ":" << _line << "] ";
            set_console_color(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
            std::cout << ">> " << _msg << '\n';
        }

        if (log_to_file) {
            std::ostringstream file_stream;
            file_stream << "[" << time_stream.str() << "] " << "[" << level_text << "] " << "[" << filename << ":" << _line << "] " << _msg;
            std::ofstream ofs(s_log_file_path_, std::ios::out | std::ios::app | std::ios::binary);
            if (ofs) {
                ofs << file_stream.str() << '\n';
            }
        }
    }

private:
    static constexpr auto get_level_text(const Level _level) -> const char* {
        switch (_level) {
        case Level::Critical:
            return "CRITICAL";
        case Level::Error:
            return "ERROR";
        case Level::Warning:
            return "WARNING";
        case Level::Info:
            return "INFO";
        case Level::Debug:
            return "DEBUG";
        case Level::Trace:
            return "TRACE";
        default:
            return "";
        }
    }

    static auto set_console_color(const WORD _color) -> void {
        const HANDLE h_console = GetStdHandle(STD_OUTPUT_HANDLE);
        SetConsoleTextAttribute(h_console, _color);
    }

    inline static auto s_file_log_level_ = Level::None;
    inline static auto s_console_log_level_ = Level::None;
    inline static std::string s_log_file_path_;
    inline static std::filesystem::path s_directory_;
    inline static std::mutex m_mutex_;
};

#define LOG_CRIT ::Logger::LogMessage(::Logger::Level::Critical, __FILE__, __LINE__)
#define LOG_ERROR ::Logger::LogMessage(::Logger::Level::Error, __FILE__, __LINE__)
#define LOG_WARNING ::Logger::LogMessage(::Logger::Level::Warning, __FILE__, __LINE__)
#define LOG_INFO ::Logger::LogMessage(::Logger::Level::Info, __FILE__, __LINE__)
#define LOG_DEBUG ::Logger::LogMessage(::Logger::Level::Debug, __FILE__, __LINE__)
#define LOG_TRACE ::Logger::LogMessage(::Logger::Level::Trace, __FILE__, __LINE__)
