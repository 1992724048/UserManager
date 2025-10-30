#pragma once
#include <filesystem>
#include <iostream>
#include <fstream>
#include <stdexcept>
#include <chrono>
#include <shared_mutex>

#include <parallel_hashmap/phmap.h>
#include <minmalloc/mimalloc.h>

using namespace std::chrono_literals;

namespace util {
    template<typename K, typename V>
    using SafeMap = phmap::parallel_flat_hash_map<K, V, phmap::priv::hash_default_hash<K>, phmap::priv::hash_default_eq<K>, mi_stl_allocator<std::pair<K, V>>, 4, std::shared_mutex>;

    auto read_file_string(const std::filesystem::path& _path) -> std::string {
        std::ifstream in(_path, std::ios::binary);
        if (!in) {
            throw std::runtime_error("Failed to open file: " + _path.string());
        }

        in.seekg(0, std::ios::end);
        const size_t size = in.tellg();
        in.seekg(0, std::ios::beg);

        if (size == 0) {
            return {};
        }

        std::string buffer;
        buffer.resize(size);
        in.read(buffer.data(), size);

        if (!in) {
            throw std::runtime_error("Failed to read file: " + _path.string());
        }

        return buffer;
    }

    auto read_file_hex(const std::filesystem::path& _path) -> std::vector<std::uint8_t> {
        std::ifstream in(_path, std::ios::binary);
        if (!in) {
            throw std::runtime_error("Failed to open file: " + _path.string());
        }

        in.seekg(0, std::ios::end);
        const size_t size = in.tellg();
        in.seekg(0, std::ios::beg);

        if (size == 0) {
            return {};
        }

        std::vector<std::uint8_t> buffer;
        buffer.resize(size);
        in.read(reinterpret_cast<char*>(buffer.data()), size);

        if (!in) {
            throw std::runtime_error("Failed to read file: " + _path.string());
        }

        return buffer;
    }

    auto app_path() -> std::filesystem::path {
        static std::filesystem::path app_path;
        if (app_path.empty()) {
            char path_out[MAX_PATH] = {};
            GetModuleFileNameA(GetModuleHandleA(nullptr), path_out, MAX_PATH);
            app_path = std::filesystem::path(path_out).parent_path();
        }
        return app_path;
    }

    inline auto get_build_time(const char* _timestamp = __TIMESTAMP__) -> std::string {
        static const std::unordered_map<std::string, std::string> month_map = {
            {"Jan", "01"},
            {"Feb", "02"},
            {"Mar", "03"},
            {"Apr", "04"},
            {"May", "05"},
            {"Jun", "06"},
            {"Jul", "07"},
            {"Aug", "08"},
            {"Sep", "09"},
            {"Oct", "10"},
            {"Nov", "11"},
            {"Dec", "12"}
        };

        std::string weekday, month, day, time, year;
        std::istringstream iss(_timestamp);
        iss >> weekday >> month >> day >> time >> year;

        if (day.size() == 1) {
            day = "0" + day;
        }

        std::string formatted = year + "-" + month_map.at(month) + "-" + day + " " + time;
        return formatted;
    }
}

#define BUILD_TIME util::get_build_time(__TIMESTAMP__)
