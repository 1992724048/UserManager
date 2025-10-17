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

#include "encode.h"

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
    class Timer final {
        std::jthread thread_;

    public:
        Timer(const Timer&) = delete;
        auto operator=(const Timer&) -> Timer& = delete;
        Timer() = default;

        auto start(int _ms, const std::function<void()>& _task) -> void {
            if (thread_.joinable()) {
                thread_.request_stop();
                thread_.join();
            }

            thread_ = std::jthread([_ms, _task](const std::stop_token& _st) {
                while (!_st.stop_requested()) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(_ms));
                    if (!_st.stop_requested()) {
                        _task();
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

    template<typename T, typename... Args>
    static auto make_mi_malloc_shared(Args&&... _args) -> std::shared_ptr<T> {
        void* mem = mi_malloc(sizeof(T));
        try {
            new(mem) T(std::forward<Args>(_args)...);
            return std::shared_ptr<T>(static_cast<T*>(mem),
                                      [](T* _ptr) {
                                          _ptr->~T();
                                          mi_free(_ptr);
                                      });
        } catch (...) {
            mi_free(mem);
            throw;
        }
    }

    template<typename K, typename V>
    using SafeMap = phmap::parallel_flat_hash_map<K, V, phmap::priv::hash_default_hash<K>, phmap::priv::hash_default_eq<K>, mi_stl_allocator<std::pair<K, V>>, 4, std::shared_mutex>;

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

        static auto list_directory(const std::filesystem::path& _directory) -> std::vector<FileInfo> {
            std::vector<FileInfo> result;
            std::error_code ec;

            for (const auto& entry : std::filesystem::directory_iterator(_directory, ec)) {
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
                              [](const FileInfo& _a, const FileInfo& _b) {
                                  if (_a.is_directory != _b.is_directory) {
                                      return _a.is_directory;
                                  }
                                  return _a.filename < _b.filename;
                              });

            return result;
        }

    private:
        static auto get_file_times(const std::filesystem::path& _path, time_t* _creation, time_t* _access, time_t* _modification) -> void {
            *_creation = *_access = *_modification = 0;
            const std::shared_ptr<void> h_file(CreateFileW(_path.wstring().c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr), CloseHandle);
            if (h_file.get() == INVALID_HANDLE_VALUE) {
                return;
            }

            FILETIME ft_create, ft_access, ft_write;
            if (!GetFileTime(h_file.get(), &ft_create, &ft_access, &ft_write)) {
                return;
            }

            auto convert_file_time = [](const FILETIME& _ft) {
                ULARGE_INTEGER ull;
                ull.LowPart = _ft.dwLowDateTime;
                ull.HighPart = _ft.dwHighDateTime;
                return (ull.QuadPart - 116444736000000000ULL) / 10000000ULL;
            };

            *_creation = static_cast<time_t>(convert_file_time(ft_create));
            *_access = static_cast<time_t>(convert_file_time(ft_access));
            *_modification = static_cast<time_t>(convert_file_time(ft_write));
        }
    };

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
        auto add(const std::string& _ip) -> void {
            const auto now = std::chrono::system_clock::now();
            const auto today = std::chrono::floor<std::chrono::days>(now);

            std::lock_guard lock(rwlock_);
            if (data_[today].insert(_ip).second) {
                async_cleanup(now - std::chrono::days(30));
            }
        }

        auto get(const std::chrono::days _days) const -> int {
            const auto cutoff = std::chrono::system_clock::now() - _days;
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

    extern auto get_mime_type(const std::string& _extension) -> std::string;
    extern auto app_path() -> std::filesystem::path;
    extern auto read_file(const std::filesystem::path& _path) -> std::string;
    extern auto generate_session_token() -> std::string;
    extern auto generate_timestamp_sha256() -> std::string;
}
