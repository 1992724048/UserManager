#pragma once
#define NOMINMAX
#include <memory>
#include <filesystem>
#include <tbb/tbb.h>
#include <ipp.h>
#include <pdh.h>
#include <pdhmsg.h>
#include <windows.h>
#include <WinSock2.h>
#include <mswsock.h>
#include <fstream>
#include <codecvt>
#include <cwchar>
#include <bcrypt.h>
#include <locale>
#include <map>
#include <unordered_set>
#include <chrono>
#include <string>
#include <shared_mutex>
#include <array>
#include <functional>
#include <cstddef>
#include <iomanip>
#include <iostream>
#include <vector>
#include <algorithm>
#include <coroutine>

#include "Logger.h"
#include "thread_pool.hpp"
#define CPPHTTPLIB_OPENSSL_SUPPORT
#define CPPHTTPLIB_ZLIB_SUPPORT
#include "httplib.h"

#include "lib/config/Config.h"
#include "mimalloc.h"

#include <openssl/rsa.h>
#include <openssl/aes.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#include <sqlite3.h>
#include <units.h>
#include <parallel_hashmap/phmap.h>

#include "fmt/format.h"

#pragma comment(lib, "pdh.lib")
#pragma comment(lib, "Mswsock.lib")

#undef max
#undef mim

using namespace units::literals;
using namespace units::length;
using namespace units::time;
using namespace units::area;
using namespace units::velocity;

namespace util {
    template<typename Ret>
    struct CoroWrapper {
        struct promise_type {
            Ret value_;

            auto get_return_object() {
                return CoroWrapper(std::coroutine_handle<promise_type>::from_promise(*this));
            }

            static auto initial_suspend() noexcept -> std::suspend_always {
                return {};
            }

            static auto final_suspend() noexcept -> std::suspend_always {
                return {};
            }

            auto return_value(Ret&& v) -> void {
                value_ = std::forward<decltype(v)>(v);
            }

            static auto unhandled_exception() -> void {
                std::terminate();
            }
        };

        explicit CoroWrapper(std::coroutine_handle<promise_type> h) : handle(h) {}

        ~CoroWrapper() {
            if (handle) {
                handle.destroy();
            }
        }

        auto operator()() -> void {
            handle.resume();
        }

        auto value() -> Ret {
            return handle.promise().value_;
        }

    private:
        std::coroutine_handle<promise_type> handle;
    };

    class Timer final {
        std::jthread thread_;

    public:
        Timer(const Timer&) = delete;
        auto operator=(const Timer&) -> Timer& = delete;
        Timer() = default;

        auto start(int ms, const std::function<void()>& task) -> void {
            if (thread_.joinable()) {
                thread_.request_stop();
                thread_.join();
            }

            thread_ = std::jthread([ms, task](const std::stop_token& st) {
                while (!st.stop_requested()) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(ms));
                    if (!st.stop_requested()) {
                        task();
                    }
                }
            });
        }

        auto stop() -> void {
            if (thread_.joinable()) {
                thread_.request_stop();
                thread_.join();
            }
        }
    };

    /**
     * @brief 时间守护结构体，用于记录和计算时间持续
     */
    struct TimeGuard {
        /**
         * @brief 使用std::chrono::steady_clock作为时钟
         */
        using Clock = std::chrono::steady_clock;
        /**
         * @brief 时间点类型
         */
        using TimePoint = Clock::time_point;

        /**
         * @brief 构造函数，初始化时间守护并记录起始时间
         */
        TimeGuard() : start(Clock::now()) {}

        /**
         * @brief 更新起始时间点为当前时间
         */
        auto update_start() -> void {
            start = Clock::now();
        }

        /**
         * @brief 获取从起始时间点到当前时间点的持续时间，以秒为单位
         * 
         * @return double 持续时间，单位为秒
         */
        [[nodiscard]] auto get_duration() const -> double {
            return std::chrono::duration<double>(Clock::now() - start).count();
        }

    private:
        /**
         * @brief 起始时间点
         */
        TimePoint start;
    };

    class Encode {
    public:
        static auto gbk_to_utf8(const std::string_view str) -> std::string {
            const int wlen = MultiByteToWideChar(936, 0, str.data(), static_cast<int>(str.size()), nullptr, 0);
            if (wlen == 0) {
                throw std::runtime_error("Failed to convert GBK to UTF-16");
            }

            std::wstring wstr(wlen, 0);
            if (MultiByteToWideChar(936, 0, str.data(), static_cast<int>(str.size()), wstr.data(), wlen) == 0) {
                throw std::runtime_error("Failed to convert GBK to UTF-16");
            }

            const int ulen = WideCharToMultiByte(CP_UTF8, 0, wstr.data(), static_cast<int>(wstr.size()), nullptr, 0, nullptr, nullptr);
            if (ulen == 0) {
                throw std::runtime_error("Failed to convert UTF-16 to UTF-8");
            }

            std::string utf8(ulen, 0);
            if (WideCharToMultiByte(CP_UTF8, 0, wstr.data(), static_cast<int>(wstr.size()), utf8.data(), ulen, nullptr, nullptr) == 0) {
                throw std::runtime_error("Failed to convert UTF-16 to UTF-8");
            }

            return utf8;
        }

        static auto utf8_to_gbk(const std::string_view str) -> std::string {
            const int wlen = MultiByteToWideChar(CP_UTF8, 0, str.data(), static_cast<int>(str.size()), nullptr, 0);
            if (wlen == 0) {
                return {};
            }

            std::wstring wstr(wlen, 0);
            if (MultiByteToWideChar(CP_UTF8, 0, str.data(), static_cast<int>(str.size()), wstr.data(), wlen) == 0) {
                throw std::runtime_error("Failed to convert UTF-8 to UTF-16");
            }

            const int glen = WideCharToMultiByte(936, 0, wstr.data(), static_cast<int>(wstr.size()), nullptr, 0, nullptr, nullptr);
            if (glen == 0) {
                throw std::runtime_error("Failed to convert UTF-16 to GBK");
            }

            std::string gbk(glen, 0);
            if (WideCharToMultiByte(936, 0, wstr.data(), static_cast<int>(wstr.size()), gbk.data(), glen, nullptr, nullptr) == 0) {
                throw std::runtime_error("Failed to convert UTF-16 to GBK");
            }

            return gbk;
        }

        static auto wchar_to_char(const std::wstring& wstr) -> std::string {
            const int len = WideCharToMultiByte(CP_ACP, 0, wstr.data(), static_cast<int>(wstr.size()), nullptr, 0, nullptr, nullptr);
            if (len == 0) {
                throw std::runtime_error("Failed to convert wide string to multibyte");
            }

            std::string str(len, 0);
            if (WideCharToMultiByte(CP_ACP, 0, wstr.data(), static_cast<int>(wstr.size()), str.data(), len, nullptr, nullptr) == 0) {
                throw std::runtime_error("Failed to convert wide string to multibyte");
            }

            return str;
        }

        static auto char_to_wchar(const std::string& str) -> std::wstring {
            const int wlen = MultiByteToWideChar(CP_ACP, 0, str.data(), static_cast<int>(str.size()), nullptr, 0);
            if (wlen == 0) {
                throw std::runtime_error("Failed to convert multibyte string to wide string");
            }

            std::wstring wstr(wlen, 0);
            if (MultiByteToWideChar(CP_ACP, 0, str.data(), static_cast<int>(str.size()), wstr.data(), wlen) == 0) {
                throw std::runtime_error("Failed to convert multibyte string to wide string");
            }

            return wstr;
        }

        static auto wchar_to_utf8(const std::wstring& wstr) -> std::string {
            const int ulen = WideCharToMultiByte(CP_UTF8, 0, wstr.data(), static_cast<int>(wstr.size()), nullptr, 0, nullptr, nullptr);
            if (ulen == 0) {
                throw std::runtime_error("Failed to convert wide string to UTF-8");
            }

            std::string utf8(ulen, 0);
            if (WideCharToMultiByte(CP_UTF8, 0, wstr.data(), static_cast<int>(wstr.size()), utf8.data(), ulen, nullptr, nullptr) == 0) {
                throw std::runtime_error("Failed to convert wide string to UTF-8");
            }

            return utf8;
        }

        static auto utf8_to_wchar(const std::string_view str) -> std::wstring {
            const int wlen = MultiByteToWideChar(CP_UTF8, 0, str.data(), static_cast<int>(str.size()), nullptr, 0);
            if (wlen == 0) {
                throw std::runtime_error("Failed to convert UTF-8 to wide string");
            }

            std::wstring wstr(wlen, 0);
            if (MultiByteToWideChar(CP_UTF8, 0, str.data(), static_cast<int>(str.size()), wstr.data(), wlen) == 0) {
                throw std::runtime_error("Failed to convert UTF-8 to wide string");
            }

            return wstr;
        }

        static auto wchar_to_gbk(const std::wstring& wstr) -> std::string {
            const int glen = WideCharToMultiByte(936, 0, wstr.data(), static_cast<int>(wstr.size()), nullptr, 0, nullptr, nullptr);
            if (glen == 0) {
                throw std::runtime_error("Failed to convert wide string to GBK");
            }

            std::string gbk(glen, 0);
            if (WideCharToMultiByte(936, 0, wstr.data(), static_cast<int>(wstr.size()), gbk.data(), glen, nullptr, nullptr) == 0) {
                throw std::runtime_error("Failed to convert wide string to GBK");
            }

            return gbk;
        }
    };

    template<typename K, typename V>
    using SafeMap = phmap::parallel_flat_hash_map<K, V, phmap::priv::hash_default_hash<K>, phmap::priv::hash_default_eq<K>, mi_stl_allocator<std::pair<K, V>>, 4, std::mutex>;

    class File {
    public:
        struct FileInfo {
            std::string filename;
            uintmax_t size;
            std::string type;
            bool is_directory;
            time_t creation_time;
            time_t access_time;
            time_t modification_time;
        };

        static auto list_directory(const std::filesystem::path& directory) -> std::vector<FileInfo> {
            std::vector<FileInfo> result;
            std::error_code ec;

            for (const auto& entry : std::filesystem::directory_iterator(directory, ec)) {
                if (ec || !entry.exists()) {
                    continue;
                }

                FileInfo info;
                info.filename = Encode::gbk_to_utf8(entry.path().filename().string());
                info.is_directory = entry.is_directory();

                if (info.is_directory) {
                    info.type = "目录";
                    info.size = 0;
                } else {
                    info.size = entry.file_size(ec);
                    if (ec) {
                        info.size = 0;
                    }

                    std::string ext = entry.path().extension().string();
                    if (!ext.empty() && ext[0] == '.') {
                        ext.erase(0, 1);
                    }
                    info.type = ext;
                }

                time_t creation, access, modification;
                get_file_times(entry.path(), &creation, &access, &modification);
                info.creation_time = creation;
                info.access_time = access;
                info.modification_time = modification;

                result.push_back(info);
            }

            std::ranges::sort(result,
                              [](const FileInfo& a, const FileInfo& b) {
                                  if (a.is_directory != b.is_directory) {
                                      return a.is_directory;
                                  }
                                  return a.filename < b.filename;
                              });

            return result;
        }

    private:
        static auto get_file_times(const std::filesystem::path& path, time_t* creation, time_t* access, time_t* modification) -> void {
            *creation = *access = *modification = 0;
            const std::shared_ptr<void> hFile(CreateFileW(path.wstring().c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr), CloseHandle);
            if (hFile.get() == INVALID_HANDLE_VALUE) {
                return;
            }

            FILETIME ftCreate, ftAccess, ftWrite;
            if (!GetFileTime(hFile.get(), &ftCreate, &ftAccess, &ftWrite)) {
                return;
            }

            auto convertFileTime = [](const FILETIME& ft) {
                ULARGE_INTEGER ull;
                ull.LowPart = ft.dwLowDateTime;
                ull.HighPart = ft.dwHighDateTime;
                return (ull.QuadPart - 116444736000000000ULL) / 10000000ULL;
            };

            *creation = static_cast<time_t>(convertFileTime(ftCreate));
            *access = static_cast<time_t>(convertFileTime(ftAccess));
            *modification = static_cast<time_t>(convertFileTime(ftWrite));
        }
    };

    template<typename T, typename... Args>
    static auto make_jemalloc_shared(Args&&... args) -> std::shared_ptr<T> {
        void* mem = mi_malloc(sizeof(T));
        try {
            new(mem) T(std::forward<Args>(args)...);
            return std::shared_ptr<T>(static_cast<T*>(mem),
                                      [](T* ptr) {
                                          ptr->~T();
                                          mi_free(ptr);
                                      });
        } catch (...) {
            mi_free(mem);
            throw;
        }
    }

    class VisitCounter {
    public:
        struct DailyStat {
            std::chrono::system_clock::time_point date;
            int unique_visitors;
        };

    private:
        mutable std::mutex rwlock_;
        std::map<std::chrono::system_clock::time_point, std::unordered_set<std::string>> data_;

        auto async_cleanup(const std::chrono::system_clock::time_point cutoff) -> void {
            const auto cutoff_day = std::chrono::floor<std::chrono::days>(cutoff);
            const auto it = data_.lower_bound(cutoff_day);
            data_.erase(data_.begin(), it);
        }

    public:
        auto add(const std::string& ip) -> void {
            const auto now = std::chrono::system_clock::now();
            const auto today = std::chrono::floor<std::chrono::days>(now);

            std::lock_guard lock(rwlock_);
            if (data_[today].insert(ip).second) {
                async_cleanup(now - std::chrono::days(30));
            }
        }

        auto get(const std::chrono::days days) const -> int {
            const auto cutoff = std::chrono::system_clock::now() - days;
            const auto cutoff_day = std::chrono::floor<std::chrono::days>(cutoff);

            std::lock_guard lock(rwlock_);
            int total = 0;
            auto it = data_.lower_bound(cutoff_day);
            for (; it != data_.end(); ++it) {
                total += it->second.size();
            }
            return total;
        }

        auto get_daily_count(const std::chrono::system_clock::time_point& day) const -> int {
            const auto target_day = std::chrono::floor<std::chrono::days>(day);

            std::lock_guard lock(rwlock_);
            if (const auto it = data_.find(target_day); it != data_.end()) {
                return it->second.size();
            }
            return 0;
        }

        auto get_daily_stats(const std::chrono::days duration) const -> std::vector<DailyStat> {
            const auto cutoff = std::chrono::system_clock::now() - duration;
            const auto cutoff_day = std::chrono::floor<std::chrono::days>(cutoff);

            std::vector<DailyStat> result;

            {
                std::lock_guard lock(rwlock_);
                auto it = data_.lower_bound(cutoff_day);
                for (; it != data_.end(); ++it) {
                    result.push_back({it->first, static_cast<int>(it->second.size())});
                }
            }

            std::ranges::sort(result,
                              [](const auto& a, const auto& b) {
                                  return a.date < b.date;
                              });

            return result;
        }

        auto contains_ip(const std::string& ip, const std::chrono::days duration) const -> bool {
            const auto cutoff = std::chrono::system_clock::now() - duration;
            const auto cutoff_day = std::chrono::floor<std::chrono::days>(cutoff);

            std::lock_guard lock(rwlock_);
            auto it = data_.lower_bound(cutoff_day);
            for (; it != data_.end(); ++it) {
                if (it->second.contains(ip)) {
                    return true;
                }
            }
            return false;
        }

        auto get_all_ips() const -> std::unordered_set<std::string> {
            std::unordered_set<std::string> unique_ips;

            std::lock_guard lock(rwlock_);
            for (const auto& ips : data_ | std::views::values) {
                unique_ips.insert(ips.begin(), ips.end());
            }

            return unique_ips;
        }

        auto get_peak_day() const -> DailyStat {
            DailyStat peak{{}, 0};

            std::lock_guard lock(rwlock_);
            for (const auto& [date, ips] : data_) {
                if (ips.size() > peak.unique_visitors) {
                    peak.date = date;
                    peak.unique_visitors = ips.size();
                }
            }

            return peak;
        }
    };

    extern auto GetMIMEType(const std::string& extension) -> std::string;
    extern auto replace_all(std::string& str, const std::string& from, const std::string& to) -> std::string&;
    extern auto app_path() -> std::filesystem::path;
    extern auto read_file(const std::filesystem::path& path) -> std::string;
    extern auto generate_session_token() -> std::string;

    inline auto generate_timestamp_sha256() -> std::string {
        const auto now = std::chrono::system_clock::now();
        const auto duration = now.time_since_epoch();
        const uint64_t micros = std::chrono::duration_cast<std::chrono::microseconds>(duration).count();

        unsigned char bytes[8];
        bytes[0] = static_cast<unsigned char>(micros >> 56);
        bytes[1] = static_cast<unsigned char>(micros >> 48);
        bytes[2] = static_cast<unsigned char>(micros >> 40);
        bytes[3] = static_cast<unsigned char>(micros >> 32);
        bytes[4] = static_cast<unsigned char>(micros >> 24);
        bytes[5] = static_cast<unsigned char>(micros >> 16);
        bytes[6] = static_cast<unsigned char>(micros >> 8);
        bytes[7] = static_cast<unsigned char>(micros);

        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(bytes, sizeof(bytes), hash);

        std::stringstream ss;
        for (const unsigned char i : hash) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned int>(i);
        }

        return ss.str();
    }
}
