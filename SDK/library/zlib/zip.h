#pragma once
#include <vector>
#include <string>
#include <stdexcept>
#include "zlib.h"

class ZipWrapper {
public:
    static auto compress(const std::vector<uint8_t>& input, int level = Z_BEST_COMPRESSION) -> std::vector<uint8_t> {
        if (input.empty()) {
            return {};
        }

        uLongf compressed_size = compressBound(input.size());
        std::vector<uint8_t> output(compressed_size);

        const int ret = compress2(output.data(), &compressed_size, input.data(), input.size(), level);
        if (ret != Z_OK) {
            throw std::runtime_error("zlib compress failed: " + std::to_string(ret));
        }

        output.resize(compressed_size);
        return output;
    }

    static auto compress(const std::string& input, int level = Z_BEST_COMPRESSION) -> std::vector<uint8_t> {
        return compress(std::vector<uint8_t>(input.begin(), input.end()), level);
    }

    static auto decompress(const std::vector<uint8_t>& input, size_t expected_size = 0) -> std::vector<uint8_t> {
        if (input.empty()) {
            return {};
        }

        uLongf decompressed_size = expected_size > 0 ? expected_size : input.size() * 4; // 初始估计
        std::vector<uint8_t> output(decompressed_size);

        int ret = uncompress(output.data(), &decompressed_size, input.data(), input.size());
        if (ret == Z_BUF_ERROR && expected_size == 0) {
            decompressed_size = input.size() * 8;
            output.resize(decompressed_size);
            ret = uncompress(output.data(), &decompressed_size, input.data(), input.size());
        }

        if (ret != Z_OK) {
            throw std::runtime_error("zlib decompress failed: " + std::to_string(ret));
        }

        output.resize(decompressed_size);
        return output;
    }

    static auto decompress_to_string(const std::vector<uint8_t>& input, size_t expected_size = 0) -> std::string {
        auto data = decompress(input, expected_size);
        return std::string(data.begin(), data.end());
    }
};
