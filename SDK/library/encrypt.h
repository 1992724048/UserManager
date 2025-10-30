#pragma once
#include <algorithm>
#include <iostream>
#include <string>
#include <array>
#include <iomanip>
#include <optional>
#include <utility>
#include <vector>

#include "openssl/md5.h"
#include "openssl/aes.h"
#include "openssl/rsa.h"
#include "openssl/pem.h"
#include "openssl/rand.h"

#include <themida/SecureEngineMacros.h>
#include <themida/SecureEngineCustomVMsMacros.h>

namespace encrypt {
    class Base64 {
    public:
        static auto encode(const std::vector<std::uint8_t>& _buf) -> std::string {
            MUTATE_START_ASM64();
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
            MUTATE_END_ASM64();
            return buff;
        }

        static auto decode(const std::string& _buf) -> std::vector<std::uint8_t> {
            MUTATE_START_ASM64();
            std::vector<std::uint8_t> buffer(_buf.size());
            BIO* b64 = BIO_new(BIO_f_base64());
            BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
            BIO* mem = BIO_new_mem_buf(_buf.data(), _buf.size());
            mem = BIO_push(b64, mem);
            BIO_read(mem, buffer.data(), _buf.size());
            BIO_free_all(mem);
            MUTATE_END_ASM64();
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

    class CRC32 {
        static auto make_table() -> std::array<std::uint32_t, 256> {
            std::array<std::uint32_t, 256> table{};
            for (std::uint32_t i = 0; i < 256; ++i) {
                std::uint32_t crc = i;
                for (std::uint32_t j = 0; j < 8; ++j) {
                    if (crc & 1) {
                        constexpr std::uint32_t poly = 0xEDB88320u;
                        crc = crc >> 1 ^ poly;
                    } else {
                        crc >>= 1;
                    }
                }
                table[i] = crc;
            }
            return table;
        }

        static inline const std::array<std::uint32_t, 256> table = make_table();

    public:
        static auto compute(const std::vector<std::uint8_t>& _data) -> std::uint32_t {
            MUTATE_START_ASM64();
            std::uint32_t crc = 0xFFFFFFFFu;
            for (const auto b : _data) {
                const auto idx = static_cast<std::uint8_t>(crc ^ b);
                crc = crc >> 8 ^ table[idx];
            }
            MUTATE_END_ASM64();
            return crc ^ 0xFFFFFFFFu;
        }
    };

    class AES {
        std::array<std::uint8_t, AES_BLOCK_SIZE> key{};
        std::array<std::uint8_t, AES_BLOCK_SIZE> iv{};

    public:
        auto key_generate() -> void {
            RAND_bytes(key.data(), key.size());
            RAND_bytes(iv.data(), iv.size());
        }

        [[nodiscard]] auto key_get() const -> const std::array<std::uint8_t, AES_BLOCK_SIZE>& {
            return key;
        }

        [[nodiscard]] auto iv_get() const -> const std::array<std::uint8_t, AES_BLOCK_SIZE>& {
            return iv;
        }

        [[nodiscard]] auto encrypt(const std::vector<std::uint8_t>& _plain) const -> std::vector<std::uint8_t> {
            if (_plain.empty()) {
                return {};
            }

            AES_KEY aes_key;
            AES_set_encrypt_key(key.data(), key.size() * 8, &aes_key);

            const size_t padding = AES_BLOCK_SIZE - (_plain.size() % AES_BLOCK_SIZE);
            std::vector<std::uint8_t> data = _plain;
            data.insert(data.end(), padding, static_cast<std::uint8_t>(padding));

            std::vector<std::uint8_t> out(data.size());
            std::array<std::uint8_t, AES_BLOCK_SIZE> iv_copy = iv;
            AES_cbc_encrypt(data.data(), out.data(), data.size(), &aes_key, iv_copy.data(), AES_ENCRYPT);

            return out;
        }

        [[nodiscard]] auto decrypt(const std::vector<std::uint8_t>& _cipher) const -> std::vector<std::uint8_t> {
            if (_cipher.empty()) {
                return {};
            }

            AES_KEY aes_key;
            AES_set_decrypt_key(key.data(), key.size() * 8, &aes_key);

            std::vector<std::uint8_t> out(_cipher.size());
            std::array<std::uint8_t, AES_BLOCK_SIZE> iv_copy = iv;
            AES_cbc_encrypt(_cipher.data(), out.data(), _cipher.size(), &aes_key, iv_copy.data(), AES_DECRYPT);

            if (!out.empty()) {
                const std::uint8_t pad = out.back();
                if (pad > 0 && pad <= AES_BLOCK_SIZE && pad <= out.size()) {
                    out.resize(out.size() - pad);
                }
            }

            return out;
        }
    };

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
            MUTATE_START_ASM64();
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
            MUTATE_END_ASM64();
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
            MUTATE_START_ASM64();
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
            MUTATE_END_ASM64();
            return {};
        }
    };

    class ECC {
        std::vector<std::uint8_t> parity;

    public:
        auto get_parity() -> std::vector<std::uint8_t>& {
            return parity;
        }

        auto encode(const std::vector<std::uint8_t>& data, const int ecc_len) -> std::vector<std::uint8_t> {
            ensure_tables();
            if (ecc_len <= 0) {
                return {};
            }

            const std::vector<int> gen = rs_generator_poly(ecc_len);

            std::vector<int> msg(data.begin(), data.end());
            msg.insert(msg.end(), ecc_len, 0);

            for (size_t i = 0; i < data.size(); ++i) {
                const int coef = msg[i];
                if (coef != 0) {
                    const int log_coef = gf_log[coef];
                    for (int j = 0; std::cmp_less(j, gen.size()); ++j) {
                        const int g = gen[j];
                        if (g != 0) {
                            msg[i + j] ^= gf_mul_exp(log_coef, g);
                        }
                    }
                }
            }

            std::vector<std::uint8_t> parity(ecc_len);
            const size_t start = data.size();
            for (int i = 0; i < ecc_len; ++i) {
                parity[i] = static_cast<std::uint8_t>(msg[start + i]);
            }
            return parity;
        }

        auto verify(const std::vector<std::uint8_t>& data, const std::vector<std::uint8_t>& parity) -> bool {
            ensure_tables();
            const int ecc_len = static_cast<int>(parity.size());
            if (ecc_len == 0) {
                return true;
            }

            const std::vector<int> s = calc_syndromes(data, parity, ecc_len);
            return std::ranges::all_of(s,
                                       [](const int _v) {
                                           return _v == 0;
                                       });
        }
    private:
        bool tables_ready = false;
        std::array<int, 512> gf_exp{};
        std::array<int, 256> gf_log{};

        auto ensure_tables() -> void {
            if (tables_ready) {
                return;
            }

            int x = 1;
            for (int i = 0; i < 255; ++i) {
                gf_exp[i] = x;
                gf_log[x] = i;
                x <<= 1;
                if (x & 0x100) {
                    constexpr int prim = 0x11d;
                    x ^= prim;
                }
            }
            for (int i = 255; i < 512; ++i) {
                gf_exp[i] = gf_exp[i - 255];
            }
            gf_exp[255] = gf_exp[0];
            gf_log[0] = -1;
            tables_ready = true;
        }

        [[nodiscard]] auto gf_mul_exp(const int log_a, const int log_b) const -> int {
            return gf_mul_from_logs(log_a, log_b);
        }

        [[nodiscard]] auto gf_mul(const int a, const int b) const -> int {
            if (a == 0 || b == 0) {
                return 0;
            }
            const int la = gf_log[a];
            const int lb = gf_log[b];
            const int res = gf_exp[la + lb];
            return res;
        }

        [[nodiscard]] auto gf_mul_from_logs(const int log_a, const int val_b) const -> int {
            if (log_a < 0 || val_b == 0) {
                return 0;
            }
            const int lb = gf_log[val_b];
            if (lb < 0) {
                return 0;
            }
            return gf_exp[log_a + lb];
        }

        [[nodiscard]] auto gf_pow(const int a, const int power) const -> int {
            if (power == 0) {
                return 1;
            }
            if (a == 0) {
                return 0;
            }
            const int l = gf_log[a];
            int idx = (l * power) % 255;
            if (idx < 0) {
                idx += 255;
            }
            return gf_exp[idx];
        }

        [[nodiscard]] auto gf_div(const int a, const int b) const -> int {
            if (b == 0) {
                throw std::runtime_error("GF divide by zero");
            }
            if (a == 0) {
                return 0;
            }
            const int la = gf_log[a], lb = gf_log[b];
            int idx = la - lb;
            while (idx < 0) {
                idx += 255;
            }
            return gf_exp[idx];
        }

        [[nodiscard]] auto poly_mul(const std::vector<int>& a, const std::vector<int>& b) const -> std::vector<int> {
            std::vector res(a.size() + b.size() - 1, 0);
            for (size_t i = 0; i < a.size(); ++i) {
                for (size_t j = 0; j < b.size(); ++j) {
                    res[i + j] ^= gf_mul(a[i], b[j]);
                }
            }
            return res;
        }

        [[nodiscard]] auto rs_generator_poly(const int nsym) const -> std::vector<int> {
            std::vector g = {1};
            for (int i = 0; i < nsym; ++i) {
                std::vector term = {1, gf_exp[i]};
                g = poly_mul(g, term);
            }
            return g;
        }

        [[nodiscard]] auto calc_syndromes(const std::vector<std::uint8_t>& data, const std::vector<std::uint8_t>& parity, const int nsym) const -> std::vector<int> {
            std::vector synd(nsym, 0);
            std::vector<int> code;
            code.reserve(data.size() + parity.size());
            for (const auto b : data) {
                code.push_back(b);
            }
            for (const auto b : parity) {
                code.push_back(b);
            }

            for (int i = 0; i < nsym; ++i) {
                int eval = 0;
                const int a = gf_exp[i];
                for (const int j : code) {
                    eval = gf_mul(eval, a) ^ j;
                }
                synd[i] = eval;
            }
            return synd;
        }
    };
}
