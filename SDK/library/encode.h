#pragma once
#include <string>
#include <stdexcept>
#include <windows.h>

class Encode {
public:
    static auto gbk_to_utf8(const std::string_view _str) -> std::string {
        if (_str.empty()) {
            return {};
        }

        const int wlen = MultiByteToWideChar(936, 0, _str.data(), static_cast<int>(_str.size()), nullptr, 0);
        if (wlen == 0) {
            throw std::runtime_error("Failed to convert GBK to UTF-16");
        }

        std::wstring wstr(wlen, 0);
        if (MultiByteToWideChar(936, 0, _str.data(), static_cast<int>(_str.size()), wstr.data(), wlen) == 0) {
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

    static auto utf8_to_gbk(const std::string_view _str) -> std::string {
        if (_str.empty()) {
            return {};
        }

        const int wlen = MultiByteToWideChar(CP_UTF8, 0, _str.data(), static_cast<int>(_str.size()), nullptr, 0);
        if (wlen == 0) {
            throw std::runtime_error("Failed to convert UTF-8 to UTF-16");
        }

        std::wstring wstr(wlen, 0);
        if (MultiByteToWideChar(CP_UTF8, 0, _str.data(), static_cast<int>(_str.size()), wstr.data(), wlen) == 0) {
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

    static auto wchar_to_char(const std::wstring& _wstr) -> std::string {
        if (_wstr.empty()) {
            return {};
        }

        const int len = WideCharToMultiByte(CP_ACP, 0, _wstr.data(), static_cast<int>(_wstr.size()), nullptr, 0, nullptr, nullptr);
        if (len == 0) {
            throw std::runtime_error("Failed to convert wide string to multibyte");
        }

        std::string str(len, 0);
        if (WideCharToMultiByte(CP_ACP, 0, _wstr.data(), static_cast<int>(_wstr.size()), str.data(), len, nullptr, nullptr) == 0) {
            throw std::runtime_error("Failed to convert wide string to multibyte");
        }

        return str;
    }

    static auto char_to_wchar(const std::string& _str) -> std::wstring {
        if (_str.empty()) {
            return {};
        }

        const int wlen = MultiByteToWideChar(CP_ACP, 0, _str.data(), static_cast<int>(_str.size()), nullptr, 0);
        if (wlen == 0) {
            throw std::runtime_error("Failed to convert multibyte string to wide string");
        }

        std::wstring wstr(wlen, 0);
        if (MultiByteToWideChar(CP_ACP, 0, _str.data(), static_cast<int>(_str.size()), wstr.data(), wlen) == 0) {
            throw std::runtime_error("Failed to convert multibyte string to wide string");
        }

        return wstr;
    }

    static auto wchar_to_utf8(const std::wstring& _wstr) -> std::string {
        if (_wstr.empty()) {
            return {};
        }

        const int ulen = WideCharToMultiByte(CP_UTF8, 0, _wstr.data(), static_cast<int>(_wstr.size()), nullptr, 0, nullptr, nullptr);
        if (ulen == 0) {
            throw std::runtime_error("Failed to convert wide string to UTF-8");
        }

        std::string utf8(ulen, 0);
        if (WideCharToMultiByte(CP_UTF8, 0, _wstr.data(), static_cast<int>(_wstr.size()), utf8.data(), ulen, nullptr, nullptr) == 0) {
            throw std::runtime_error("Failed to convert wide string to UTF-8");
        }

        return utf8;
    }

    static auto utf8_to_wchar(const std::string_view _str) -> std::wstring {
        if (_str.empty()) {
            return {};
        }

        const int wlen = MultiByteToWideChar(CP_UTF8, 0, _str.data(), static_cast<int>(_str.size()), nullptr, 0);
        if (wlen == 0) {
            throw std::runtime_error("Failed to convert UTF-8 to wide string");
        }

        std::wstring wstr(wlen, 0);
        if (MultiByteToWideChar(CP_UTF8, 0, _str.data(), static_cast<int>(_str.size()), wstr.data(), wlen) == 0) {
            throw std::runtime_error("Failed to convert UTF-8 to wide string");
        }

        return wstr;
    }

    static auto wchar_to_gbk(const std::wstring& _wstr) -> std::string {
        if (_wstr.empty()) {
            return {};
        }

        const int glen = WideCharToMultiByte(936, 0, _wstr.data(), static_cast<int>(_wstr.size()), nullptr, 0, nullptr, nullptr);
        if (glen == 0) {
            throw std::runtime_error("Failed to convert wide string to GBK");
        }

        std::string gbk(glen, 0);
        if (WideCharToMultiByte(936, 0, _wstr.data(), static_cast<int>(_wstr.size()), gbk.data(), glen, nullptr, nullptr) == 0) {
            throw std::runtime_error("Failed to convert wide string to GBK");
        }

        return gbk;
    }
};
