#pragma once
#include <array>

constexpr auto ct_hash(const char* _data, const size_t _size) -> uint32_t {
    uint32_t hash = 0x811C9DC5;
    for (size_t i = 0; i < _size; ++i) {
        hash = (hash ^ static_cast<unsigned char>(_data[i])) * 0x01000193;
    }
    return hash;
}

constexpr auto ct_rand(const uint32_t _seed) -> uint32_t {
    return 1103515245u * _seed + 12345u & 0x7fffffff;
}

template<typename CharT, size_t N, uint32_t Seed>
class XorStr {
    std::array<CharT, N> encrypted{};
    CharT key;

public:
    explicit constexpr XorStr(const CharT (&_str)[N]) : key(static_cast<CharT>(Seed % 0xFF + 1)) {
        for (size_t i = 0; i < N; ++i) {
            encrypted[i] = _str[i] ^ key;
        }
    }

    [[nodiscard]] auto decrypt() const {
        struct Decrypted {
            std::array<CharT, N> buf{};

            constexpr Decrypted(const std::array<CharT, N>& _enc, CharT _key) {
                for (size_t i = 0; i < N; ++i) {
                    buf[i] = _enc[i] ^ _key;
                }
            }

            explicit constexpr operator const CharT*() const {
                return buf.data();
            }
        };
        return Decrypted{encrypted, key};
    }
};

#define CT_SEED (ct_hash(__TIME__, sizeof(__TIME__)))
#define XORSTR(str)  (XorStr<char,    sizeof(str) / sizeof(*(str)), ct_rand(CT_SEED + __COUNTER__)> { str }.decrypt()).buf.data()
#define XORWSTR(str) (XorStr<wchar_t, sizeof(str) / sizeof(*(str)), ct_rand(CT_SEED + __COUNTER__)> { str }.decrypt()).buf.data()
