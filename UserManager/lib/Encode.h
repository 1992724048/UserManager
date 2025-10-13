#pragma once
#include <bcrypt.h>
#include <codecvt>
#include <cwchar>
#include <locale>
#include <string>

namespace encode {
	static auto GbkToUtf8(const std::string& str) -> std::string {
		const auto GBK_LOCALE_NAME = ".936";
		std::wstring_convert convert(new std::codecvt_byname<wchar_t, char, mbstate_t>(GBK_LOCALE_NAME));
		const std::wstring tmp_wstr = convert.from_bytes(str);
		std::wstring_convert<std::codecvt_utf8<wchar_t>> cv2;
		return cv2.to_bytes(tmp_wstr);
	}

	static auto Utf8ToGbk(const std::string& str) -> std::string {
		std::wstring_convert<std::codecvt_utf8<wchar_t>> conv;
		const std::wstring tmp_wstr = conv.from_bytes(str);
		const auto GBK_LOCALE_NAME = ".936";
		std::wstring_convert convert(new std::codecvt_byname<wchar_t, char, mbstate_t>(GBK_LOCALE_NAME));
		return convert.to_bytes(tmp_wstr);
	}

	static auto w2s(const std::wstring& wstr) -> std::string {
		std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
		return converter.to_bytes(wstr);
	}

	static auto s2w(const std::string& input) -> std::wstring {
		std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
		return converter.from_bytes(input);
	}
}
