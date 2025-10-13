#pragma once

#include "..\config/converters.h"
#include "FieldEntry.h"

namespace config::internal { namespace CHECK {
		struct No {};

		template <typename T, typename Arg>
		auto operator==(const T&, const Arg&) -> No;

		template <typename T, typename Arg = T>
		struct EqualExists {
			enum { value = !std::is_same_v<decltype(std::declval<T>() == std::declval<Arg>()), No> };
		};
	}

	template <typename T>
	class FieldSerialize : public FieldEntry {
	public:
		FieldSerialize(const std::string& friendlyName, const std::string& name, const std::string& sectionName, const T& defaultValue, bool multiProfile = false) : FieldEntry(friendlyName, name, sectionName, multiProfile), m_Value(defaultValue), m_DefaultValue(defaultValue) {}

		auto ToJson() -> nlohmann::json override {
			if constexpr (CHECK::EqualExists<T>::value) if (m_Value == m_DefaultValue) return {};


			return converters::ToJson(m_Value);
		}

		auto FromJson(const nlohmann::json& jObject) -> void override {
			if (jObject.empty()) {
				m_Value = m_DefaultValue;
				return;
			}

			converters::FromJson(m_Value, jObject);
		}

		auto Reset() -> void override { m_Value = m_DefaultValue; }

		T m_Value;
		T m_DefaultValue;
	};
}
