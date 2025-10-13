#pragma once

#include <filesystem>
#include <memory>

#include "Field.h"
#include <vector>
#include <string>
#include "fields/Enum.h"

#include "..\events/event.hpp"

#define SNFEX(field, friendName, name, section, defaultValue, shared) config::CreateField<decltype(field)::_ValueType>(friendName, name, section, shared, defaultValue)
#define SNFB(field, name, section, defaultValue, shared) SNFEX(field, name, config::internal::FixFieldName(#field), section, defaultValue, shared)
#define SNF(field, name, section, defaultValue) SNFB(field, name, section, defaultValue, false)

#define NFEX(field, friendName, name, section, defaultValue, shared) field(SNFEX(field, friendName, name, section, defaultValue, shared))
#define NFEXUP(field, friendName, name, section, shared, ...) field(config::CreateField<decltype(field)::_ValueType>(friendName, name, section, shared, __VA_ARGS__))

#define NFB(field, name, section, defaultValue, shared) NFEX(field, name, config::internal::FixFieldName(#field), section, defaultValue, shared)
#define NFS(field, name, section, defaultValue) NFB(field, name, section, defaultValue, true)
#define NF(field, name, section, defaultValue) NFB(field, name, section, defaultValue, false)

#define NFPB(field, name, section, shared, ...) NFEXUP(field, name, config::internal::FixFieldName(#field), section, shared, __VA_ARGS__)
#define NFPS(field, name, section, ...) NFPB(field, name, section, true, __VA_ARGS__)
#define NFP(field, name, section, ...) NFPB(field, name, section, false, __VA_ARGS__)

namespace config {
	namespace internal {
		template <typename T>
		std::vector<T> s_Fields;

		auto AddField(std::shared_ptr<FieldEntry> field) -> void;

		inline auto FixFieldName(const std::string& fieldName) -> std::string {
			if (fieldName.substr(1, 1) == "_") {
				return fieldName.substr(2);
			}
			return fieldName;
		}
	}

	template <typename T, typename... Args>
	auto CreateField(const std::string& friendName, const std::string& name, const std::string& section, bool multiProfile, Args... args) -> Field<T> {
		auto newField = Field<T>(friendName, name, section, T(args...), multiProfile);
		internal::s_Fields<Field<T>>.push_back(newField);
		internal::AddField(newField.entry());
		return newField;
	}

	template <typename T>
	auto GetFields() -> std::vector<Field<T>>& {
		return internal::s_Fields<Field<T>>;
	}

	auto Initialize(const std::filesystem::path& filePath) -> void;
	auto SetupUpdate(TEvent<>*) -> void;

	auto Refresh() -> void;
	auto Save() -> void;

	auto CreateProfile(const std::string& profileName, bool moveAfterCreate = true) -> void;
	auto RemoveProfile(const std::string& profileName) -> void;
	auto RenameProfile(const std::string& oldProfileName, const std::string& newProfileName) -> void;
	auto ChangeProfile(const std::string& profileName) -> void;
	auto DuplicateProfile(const std::string& profileName) -> void;
	auto GetProfiles() -> std::vector<std::string> const&;
	auto CurrentProfileName() -> std::string const&;

	extern TEvent<> ProfileChanged;
}
