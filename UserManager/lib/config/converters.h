#pragma once

#include "..\json.hpp"

namespace config::converters {
	template <typename T>
	inline auto ToJson(const T& value) -> nlohmann::json {
		return nlohmann::json(value);
	}

	template <typename T>
	inline auto FromJson(T& value, const nlohmann::json& jObject) -> void {
		value = jObject.get<T>();
	}
}
