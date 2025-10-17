#pragma once
#include <iostream>
#include <string>
#include <type_traits>
#include <array>
#include <cstring>
#include <utility>
#include <cwchar>
#include <iomanip>
#include <sstream>
#include <vector>
#include <mimalloc-override.h>

#include "bio.h"
#include "pem.h"
#include "rsa.h"

#include "openssl/md5.h"

class Encrypt {
    inline static const std::string base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" "abcdefghijklmnopqrstuvwxyz" "0123456789+/";

public:
    static auto md5(const std::string& str) -> std::string {
        unsigned char digest[MD5_DIGEST_LENGTH];
        MD5((unsigned char*)str.c_str(), str.size(), reinterpret_cast<unsigned char*>(&digest));

        std::stringstream ss;
        for (const unsigned char i : digest) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(i);
        }
        return ss.str();
    }

    static auto is_base64(const std::uint8_t c) -> bool {
        return isalnum(c) || c == '+' || c == '/';
    }

    static auto base64_encode(const std::uint8_t* _buf, unsigned int _buf_len) -> std::string {
        std::string ret;
        int i = 0;
        std::uint8_t char_array_3[3];
        std::uint8_t char_array_4[4];

        while (_buf_len--) {
            char_array_3[i++] = *_buf++;
            if (i == 3) {
                char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
                char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
                char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
                char_array_4[3] = char_array_3[2] & 0x3f;

                for (i = 0; i < 4; i++) {
                    ret += base64_chars[char_array_4[i]];
                }
                i = 0;
            }
        }

        if (i) {
            int j;
            for (j = i; j < 3; j++) {
                char_array_3[j] = '\0';
            }

            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (j = 0; j < i + 1; j++) {
                ret += base64_chars[char_array_4[j]];
            }

            while (i++ < 3) {
                ret += '=';
            }
        }

        return ret;
    }

    static auto base64_decode(const std::string& encoded_string) -> std::vector<std::uint8_t> {
        size_t in_len = encoded_string.size();
        int i = 0;
        int in_ = 0;
        std::uint8_t char_array_4[4], char_array_3[3];
        std::vector<std::uint8_t> ret;

        while (in_len-- && encoded_string[in_] != '=' && is_base64(encoded_string[in_])) {
            char_array_4[i++] = encoded_string[in_];
            in_++;
            if (i == 4) {
                for (i = 0; i < 4; i++) {
                    char_array_4[i] = static_cast<std::uint8_t>(base64_chars.find(char_array_4[i]));
                }

                char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
                char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
                char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

                for (i = 0; i < 3; i++) {
                    ret.push_back(char_array_3[i]);
                }
                i = 0;
            }
        }

        if (i) {
            int j;
            for (j = i; j < 4; j++) {
                char_array_4[j] = 0;
            }

            for (j = 0; j < 4; j++) {
                char_array_4[j] = static_cast<std::uint8_t>(base64_chars.find(char_array_4[j]));
            }

            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

            for (j = 0; j < i - 1; j++) {
                ret.push_back(char_array_3[j]);
            }
        }

        return ret;
    }

    static auto generate_rsa_key(std::string& _out_pub_key, std::string& _out_pri_key, const int _len) -> void {
        RSA* keypair = RSA_generate_key(_len, RSA_3, nullptr, nullptr);

        BIO* pri = BIO_new(BIO_s_mem());
        BIO* pub = BIO_new(BIO_s_mem());

        PEM_write_bio_RSAPrivateKey(pri, keypair, nullptr, nullptr, 0, nullptr, nullptr);
        PEM_write_bio_RSA_PUBKEY(pub, keypair);

        const size_t pri_len = BIO_pending(pri);
        const size_t pub_len = BIO_pending(pub);

        const auto pri_key = static_cast<char*>(malloc(pri_len + 1));
        const auto pub_key = static_cast<char*>(malloc(pub_len + 1));

        BIO_read(pri, pri_key, pri_len);
        BIO_read(pub, pub_key, pub_len);

        pri_key[pri_len] = '\0';
        pub_key[pub_len] = '\0';

        _out_pub_key = pub_key;
        _out_pri_key = pri_key;

        RSA_free(keypair);
        BIO_free_all(pub);
        BIO_free_all(pri);
        free(pri_key);
        free(pub_key);
    }
};
