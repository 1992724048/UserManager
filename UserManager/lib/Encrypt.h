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

#include "openssl/md5.h"

class Encrypt {
	inline static const std::string base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" "abcdefghijklmnopqrstuvwxyz" "0123456789+/";

public:
	static auto MD5(const std::string& str) -> std::string {
		unsigned char digest[MD5_DIGEST_LENGTH];
		::MD5((unsigned char*)str.c_str(), str.size(), reinterpret_cast<unsigned char*>(&digest));

		std::stringstream ss;
		for (unsigned char i : digest)
			ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(i);
		return ss.str();
	}

	static auto is_base64(BYTE c) -> bool {
		return (isalnum(c) || (c == '+') || (c == '/'));
	}

	static auto Base64_Encode(const BYTE* buf, unsigned int bufLen) -> std::string {
		std::string ret;
		int i = 0;
		int j = 0;
		BYTE char_array_3[3];
		BYTE char_array_4[4];

		while (bufLen--) {
			char_array_3[i++] = *(buf++);
			if (i == 3) {
				char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
				char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
				char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
				char_array_4[3] = char_array_3[2] & 0x3f;

				for (i = 0; (i < 4); i++)
					ret += base64_chars[char_array_4[i]];
				i = 0;
			}
		}

		if (i) {
			for (j = i; j < 3; j++)
				char_array_3[j] = '\0';

			char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
			char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
			char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
			char_array_4[3] = char_array_3[2] & 0x3f;

			for (j = 0; (j < i + 1); j++)
				ret += base64_chars[char_array_4[j]];

			while ((i++ < 3))
				ret += '=';
		}

		return ret;
	}

	static auto Base64_Decode(const std::string& encoded_string) -> std::vector<BYTE> {
		size_t in_len = encoded_string.size();
		int i = 0;
		int j = 0;
		int in_ = 0;
		BYTE char_array_4[4], char_array_3[3];
		std::vector<BYTE> ret;

		while (in_len-- && (encoded_string[in_] != '=') && is_base64(encoded_string[in_])) {
			char_array_4[i++] = encoded_string[in_];
			in_++;
			if (i == 4) {
				for (i = 0; i < 4; i++)
					char_array_4[i] = static_cast<BYTE>(base64_chars.find(char_array_4[i])); // base64_chars len < 255

				char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
				char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
				char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

				for (i = 0; (i < 3); i++)
					ret.push_back(char_array_3[i]);
				i = 0;
			}
		}

		if (i) {
			for (j = i; j < 4; j++)
				char_array_4[j] = 0;

			for (j = 0; j < 4; j++)
				char_array_4[j] = static_cast<BYTE>(base64_chars.find(char_array_4[j]));

			char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
			char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
			char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

			for (j = 0; (j < i - 1); j++)
				ret.push_back(char_array_3[j]);
		}

		return ret;
	}
};
