#pragma once
#include <iostream>
#include <string>
#include <array>
#include <iomanip>
#include <optional>
#include <vector>
#include <mimalloc-override.h>
#include <mimalloc-new-delete.h>

#include "openssl/md5.h"
#include "openssl/aes.h"
#include "openssl/rsa.h"
#include "openssl/pem.h"

namespace encrypt {
    class Base64 {
    public:
        static auto encode(const std::vector<std::uint8_t>& _buf) -> std::string {
            BIO* b64 = BIO_new(BIO_f_base64());
            BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
            BIO* mem = BIO_new(BIO_s_mem());
            b64 = BIO_push(b64, mem);
            BIO_write(b64, _buf.data(), _buf.size());
            BIO_flush(b64);
            BUF_MEM* ptr = nullptr;
            BIO_get_mem_ptr(b64, &ptr);
            std::string buff(ptr->length + 1, '\0');
            std::memcpy(buff.data(), ptr->data, ptr->length);
            BIO_free_all(b64);
            return buff;
        }

        static auto decode(const std::string& _buf) -> std::vector<std::uint8_t> {
            std::vector<std::uint8_t> buffer(_buf.size());
            BIO* b64 = BIO_new(BIO_f_base64());
            BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
            BIO* mem = BIO_new_mem_buf(_buf.data(), _buf.size());
            mem = BIO_push(b64, mem);
            BIO_read(mem, buffer.data(), _buf.size());
            BIO_free_all(mem);
            return buffer;
        }
    };

    class MD5 {
    public:
        static auto encode(const std::vector<std::uint8_t>& _data) -> std::vector<std::uint8_t> {
            std::vector<std::uint8_t> digest(MD5_DIGEST_LENGTH, 0x00);
            ::MD5(_data.data(), _data.size(), digest.data());
            return digest;
        }
    };

    class AES {};

    class RSA {
        std::string pub_key;
        std::string pri_key;

    public:
        auto key_pub() -> std::string& {
            return pub_key;
        }

        auto key_pri() -> std::string& {
            return pri_key;
        }

        auto key_generate(const int _len = 8192) -> void {
            const auto keypair = RSA_generate_key(_len, RSA_3, nullptr, nullptr);

            const auto pri = BIO_new(BIO_s_mem());
            const auto pub = BIO_new(BIO_s_mem());

            PEM_write_bio_RSAPrivateKey(pri, keypair, nullptr, nullptr, 0, nullptr, nullptr);
            PEM_write_bio_RSA_PUBKEY(pub, keypair);

            const size_t pri_len = BIO_pending(pri);
            const size_t pub_len = BIO_pending(pub);

            std::string pri_key(pri_len + 1, '\0');
            std::string pub_key(pub_len + 1, '\0');

            BIO_read(pri, pri_key.data(), pri_len);
            BIO_read(pub, pub_key.data(), pub_len);

            RSA_free(keypair);
            BIO_free_all(pri);
            BIO_free_all(pub);

            this->pub_key = std::move(pub_key);
            this->pri_key = std::move(pri_key);
        }

        [[nodiscard]] auto pri_encode(const std::vector<std::uint8_t>& _data) const -> std::vector<std::uint8_t> {
            return encode_decode(_data);
        }

        [[nodiscard]] auto pri_decode(const std::vector<std::uint8_t>& _data) const -> std::vector<std::uint8_t> {
            return encode_decode(_data, false, true);
        }

        [[nodiscard]] auto pub_encode(const std::vector<std::uint8_t>& _data) const -> std::vector<std::uint8_t> {
            return encode_decode(_data, true, false);
        }

        [[nodiscard]] auto pub_decode(const std::vector<std::uint8_t>& _data) const -> std::vector<std::uint8_t> {
            return encode_decode(_data, true, true);
        }

    private:
        [[nodiscard]] auto encode_decode(const std::vector<std::uint8_t>& _data, const bool _pub = false, const bool _decode = false) const -> std::vector<std::uint8_t> {
            if (_data.empty()) {
                return {};
            }

            const auto key_bio = BIO_new_mem_buf(_pub ? this->pub_key.data() : this->pri_key.data(), -1);
            ::RSA* rsa = RSA_new();
            if (_pub) {
                rsa = PEM_read_bio_RSA_PUBKEY(key_bio, &rsa, nullptr, nullptr);
            } else {
                rsa = PEM_read_bio_RSAPrivateKey(key_bio, &rsa, nullptr, nullptr);
            }

            if (rsa) {
                std::vector<std::uint8_t> buffer(RSA_size(rsa));
                if (_pub) {
                    _decode
                        ? RSA_public_decrypt(_data.size(), _data.data(), buffer.data(), rsa, RSA_PKCS1_PADDING)
                        : RSA_public_encrypt(_data.size(), _data.data(), buffer.data(), rsa, RSA_PKCS1_PADDING);
                } else {
                    _decode
                        ? RSA_private_decrypt(_data.size(), _data.data(), buffer.data(), rsa, RSA_PKCS1_PADDING)
                        : RSA_private_encrypt(_data.size(), _data.data(), buffer.data(), rsa, RSA_PKCS1_PADDING);
                }

                RSA_free(rsa);
                BIO_free_all(key_bio);
                return buffer;
            }

            RSA_free(rsa);
            BIO_free_all(key_bio);
            return {};
        }
    };
}
