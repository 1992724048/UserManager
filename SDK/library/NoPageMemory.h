#pragma once
#include <ntcall.h>
#include <mutex>
#include <stdexcept>
#include <format>
#include <type_traits>
#include <Windows.h>

#include "encrypt.h"

template<typename T> concept NonZeroSize = sizeof(T) > 0;

template<NonZeroSize T>
class NoPageMemory final {
    HANDLE section_handle = nullptr;
    LARGE_INTEGER maximum_size{};
    std::mutex mutex;
    uint8_t xor_key = 0;
    std::uint32_t crc32;

public:
    NoPageMemory() {
        std::random_device rd;
        xor_key = static_cast<uint8_t>(rd() & 0xFF) + 0x01;

        SYSTEM_INFO si;
        GetSystemInfo(&si);
        const SIZE_T granularity = si.dwAllocationGranularity;
        maximum_size.QuadPart = (sizeof(T) + granularity - 1) / granularity * granularity;

        OBJECT_ATTRIBUTES obj;
        InitializeObjectAttributes(&obj, nullptr, 0, nullptr, nullptr);
        auto status = sys::NtCreateSection(&section_handle, SECTION_ALL_ACCESS, &obj, &maximum_size, PAGE_EXECUTE_READWRITE, SEC_COMMIT, nullptr);
        if (status != 0) {
            throw std::runtime_error(std::format("[NPM] NtCreateSection failed : {}", status));
        }
    }

    ~NoPageMemory() {
        if (section_handle) {
            sys::NtClose(section_handle);
        }
    }

    auto operator=(const T& _value) -> NoPageMemory& {
        set(_value);
        return *this;
    }

    explicit operator T() {
        return get();
    }

    [[nodiscard]] auto get() -> T {
        std::scoped_lock lock(mutex);
        T* ptr = const_cast<NoPageMemory*>(this)->mmap(PAGE_READONLY);
        T value;

        if constexpr (std::is_trivially_copyable_v<T>) {
            std::memcpy(&value, ptr, sizeof(T));
        } else {
            value = *ptr;
        }

        std::vector<std::uint8_t> data(sizeof(T));
        std::memcpy(data.data(), &value, sizeof(T));
        if (crc32 != encrypt::CRC32::compute(data)) {
            std::thread(std::terminate).detach();
        }
        xor_buffer(reinterpret_cast<uint8_t*>(&value), sizeof(T));
        umap(ptr);
        return value;
    }

    auto set(const T& _value) -> void {
        std::scoped_lock lock(mutex);
        T* ptr = mmap();

        if constexpr (std::is_trivially_copyable_v<T>) {
            T temp = _value;
            std::memcpy(ptr, &temp, sizeof(T));
        } else {
            *ptr = _value;
        }

        xor_buffer(reinterpret_cast<uint8_t*>(ptr), sizeof(T));
        std::vector<std::uint8_t> data(sizeof(T));
        std::memcpy(data.data(), ptr, sizeof(T));
        crc32 = encrypt::CRC32::compute(data);
        umap(ptr);
    }

    auto operator==(const NoPageMemory& _other) -> bool {
        return get() == _other.get();
    }

    auto operator!=(const NoPageMemory& _other) -> bool {
        return !(*this == _other);
    }

    auto operator==(const T& _value) -> bool {
        return get() == _value;
    }

    auto operator!=(const T& _value) -> bool {
        return !(*this == _value);
    }

private:
    auto mmap(const ULONG _protect = PAGE_READWRITE) -> T* {
        PVOID address = nullptr;
        LARGE_INTEGER offset_size{};
        SIZE_T view_size = maximum_size.QuadPart;

        auto status = sys::NtMapViewOfSection(section_handle, GetCurrentProcess(), &address, 0, 0, &offset_size, &view_size, sys::ViewUnmap, 0, _protect);
        if (status != 0) {
            throw std::runtime_error(std::format("[NPM] NtMapViewOfSection failed : {}", status));
        }

        return static_cast<T*>(address);
    }

    static auto umap(T* _address) -> void {
        sys::NtUnmapViewOfSection(GetCurrentProcess(), _address);
    }

    auto xor_buffer(uint8_t* _data, const size_t _size) const noexcept -> void {
        for (size_t i = 0; i < _size; ++i) {
            _data[i] ^= xor_key;
        }
    }
};


class DynamicMemory final {
    HANDLE section_handle = nullptr;
    LARGE_INTEGER maximum_size;
    std::mutex mutex;

public:
    DynamicMemory(const size_t _initial_size = 4096) {
        maximum_size.QuadPart = _initial_size;
        OBJECT_ATTRIBUTES obj;
        InitializeObjectAttributes(&obj, nullptr, 0, nullptr, nullptr);

        auto status = sys::NtCreateSection(&section_handle, SECTION_ALL_ACCESS, &obj, &maximum_size, PAGE_EXECUTE_READWRITE, SEC_COMMIT, nullptr);
        if (status != 0) {
            throw std::runtime_error(std::format("[NPM] NtCreateSection failed: {}", status));
        }
    }

    ~DynamicMemory() {
        if (section_handle) {
            sys::NtClose(section_handle);
        }
    }

    auto write(const void* _data, const size_t _size, const size_t _offset = 0) -> void {
        std::scoped_lock lock(mutex);
        if (_offset + _size > maximum_size.QuadPart) {
            throw std::out_of_range("[NPM] Write exceeds memory size");
        }
        void* ptr = mmap(_offset, _size);
        std::memcpy(ptr, _data, _size);
        umap(ptr);
    }

    auto read(void* _buffer, const size_t _size, const size_t _offset = 0) -> void {
        std::scoped_lock lock(mutex);
        if (_offset + _size > maximum_size.QuadPart) {
            throw std::out_of_range("[NPM] Read exceeds memory size");
        }
        void* ptr = mmap(_offset, _size, PAGE_READONLY);
        std::memcpy(_buffer, ptr, _size);
        umap(ptr);
    }

    auto resize(const size_t _new_size) -> void {
        std::scoped_lock lock(mutex);
        LARGE_INTEGER new_max;
        new_max.QuadPart = _new_size;

        sys::NtClose(section_handle);

        OBJECT_ATTRIBUTES obj;
        InitializeObjectAttributes(&obj, nullptr, 0, nullptr, nullptr);
        auto status = sys::NtCreateSection(&section_handle, SECTION_ALL_ACCESS, &obj, &new_max, PAGE_EXECUTE_READWRITE, SEC_COMMIT, nullptr);

        if (status != 0) {
            throw std::runtime_error(std::format("[NPM] NtCreateSection failed during resize: {}", status));
        }

        maximum_size = new_max;
    }

    [[nodiscard]] auto size() const -> size_t {
        return static_cast<size_t>(maximum_size.QuadPart);
    }

private:
    [[nodiscard]] auto mmap(const size_t _offset, const size_t _view_size, const ULONG _protect = PAGE_READWRITE) const -> void* {
        PVOID address = nullptr;
        LARGE_INTEGER offset_li;
        offset_li.QuadPart = _offset;
        SIZE_T sz = _view_size;

        auto status = sys::NtMapViewOfSection(section_handle, GetCurrentProcess(), &address, 0, 0, &offset_li, &sz, sys::ViewUnmap, 0, _protect);
        if (status != 0) {
            throw std::runtime_error(std::format("[NPM] NtMapViewOfSection failed: {}", status));
        }

        return address;
    }

    static auto umap(void* _addr) -> void {
        sys::NtUnmapViewOfSection(GetCurrentProcess(), _addr);
    }
};
