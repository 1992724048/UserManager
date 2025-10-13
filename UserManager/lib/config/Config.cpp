#include "config.h"

#include <atomic>
#include <fstream>

#include "../json.hpp"

#include <mutex>

#include "../../Logger.h"

namespace config {
	TEvent<> ProfileChanged;

	static std::filesystem::path s_Filepath;
	static nlohmann::json s_ConfigRoot;
	static nlohmann::json s_EmptyJObject = nlohmann::json::object();

	// Little speed-up
	static nlohmann::json* s_ProfileRoot = nullptr;
	static nlohmann::json* s_Profiles = nullptr;
	static nlohmann::json* s_SharedRoot = nullptr;

	static std::mutex s_ProfileMutex;
	static std::string s_ProfileName;
	static std::vector<std::string> s_ProfilesNames;

	static constexpr int c_SaveDelay = 2000;
	static TEvent<>* s_UpdateEvent = nullptr;
	static std::atomic<int64_t> s_NextSaveTimestamp = 0;

	static std::vector<std::shared_ptr<internal::FieldEntry>> s_Entries;

	auto StringSplit(const std::string& delimiter, const std::string& content) -> std::vector<std::string> {
		std::vector<std::string> tokens;
		size_t pos;
		size_t prevPos = 0;
		while ((pos = content.find(delimiter, prevPos)) != std::string::npos) {
			std::string token = content.substr(prevPos, pos - prevPos);
			tokens.push_back(token);
			prevPos = pos + delimiter.length();
		}
		tokens.push_back(content.substr(prevPos));
		return tokens;
	}

	auto LoadFile() -> void {
		std::ifstream fileInput(s_Filepath, std::ios::in);
		if (!fileInput.is_open()) {
			LOG_DEBUG << "打开配置文件失败，可能是第一次启动.";
			return;
		}

		try {
			s_ConfigRoot = nlohmann::json::parse(fileInput);
		} catch (nlohmann::json::parse_error& ex) {
			LOG_ERROR << "按字节解析错误:" << ex.byte;
		}
	}

	auto UpdateProfilesNames() -> void {
		std::lock_guard _lock(s_ProfileMutex);
		s_ProfilesNames.clear();
		for (auto& [name, _] : s_Profiles->items())
			s_ProfilesNames.push_back(name);
	}

	auto Initialize(const std::filesystem::path& filePath) -> void {
		s_ConfigRoot = {};
		s_Filepath = filePath;
		LoadFile();

		if (!s_ConfigRoot.contains("current_profile")) {
			s_ConfigRoot = {
				{
					"shared",
					{}
				},
				{
					"profiles",
					{}
				},
				{
					"current_profile",
					""
				}
			};
		}

		s_Profiles = &s_ConfigRoot["profiles"];
		s_SharedRoot = &s_ConfigRoot["shared"];

		if (s_ConfigRoot["current_profile"].empty()) {
			CreateProfile("default");
		} else {
			ChangeProfile(s_ConfigRoot["current_profile"]);
		}

		UpdateProfilesNames();
	}

	auto OnUpdate() -> void;

	auto SetupUpdate(TEvent<>* updateEvent) -> void {
		s_UpdateEvent = updateEvent;
		(*s_UpdateEvent) += FUNCTION_HANDLER(OnUpdate);
	}

	auto UpdateSaveTimestamp() -> void {
		if (!s_UpdateEvent) {
			return;
		}

		if (s_NextSaveTimestamp != 0) {
			return;
		}

		s_NextSaveTimestamp = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count() + c_SaveDelay;
	}

	auto ResetNotShared() -> void {
		for (auto& entry : s_Entries) {
			if (!entry->IsShared()) {
				entry->Reset();
			}
		}
	}

	auto GetFieldJsonContainer(internal::FieldEntry* field, bool create = false) -> nlohmann::json& {
		if (field->GetContainer() != nullptr) {
			return *field->GetContainer();
		}

		nlohmann::json* rootContainer = s_ProfileRoot;
		if (field->IsShared()) {
			rootContainer = s_SharedRoot;
		}

		auto sectionParts = StringSplit("::", field->GetSection());
		for (auto& part : sectionParts) {
			if (!rootContainer->contains(part)) {
				if (!create) {
					return s_EmptyJObject;
				}

				(*rootContainer)[part] = {};
			}

			rootContainer = &(*rootContainer)[part];
		}

		auto& sectionContainer = *rootContainer;
		if (!sectionContainer.contains(field->GetName())) {
			if (!create) {
				return s_EmptyJObject;
			}

			sectionContainer[field->GetName()] = {};
		}

		auto& fieldContainer = sectionContainer[field->GetName()];
		field->SetContainer(&fieldContainer);
		return fieldContainer;
	}

	auto RemoveFieldContainer(internal::FieldEntry* field, const std::string& section, const std::string& name, bool shared) -> void {
		field->SetContainer(nullptr);

		nlohmann::json* rootContainer = s_ProfileRoot;
		if (shared) {
			rootContainer = s_SharedRoot;
		}

		auto sectionParts = StringSplit("::", section);
		std::list<std::pair<std::string, nlohmann::json*>> nodePath;
		for (auto& part : sectionParts) {
			if (!rootContainer->contains(part)) {
				return;
			}

			nodePath.emplace_front(part, rootContainer);
			rootContainer = &(*rootContainer)[part];
		}

		if (!rootContainer->contains(name)) {
			return;
		}

		rootContainer->erase(name);
		for (auto& [key, node] : nodePath) {
			if (!(*node)[key].empty()) {
				break;
			}

			node->erase(key);
		}
	}

	auto UpdateField(internal::FieldEntry* field) -> void {
		auto& fieldContainer = GetFieldJsonContainer(field);
		field->FromJson(fieldContainer);
	}

	auto UpdateNotShared() -> void {
		ResetNotShared();
		for (auto& entry : s_Entries) {
			if (!entry->IsShared()) {
				UpdateField(entry.get());
			}
		}
	}

	auto LoadField(internal::FieldEntry* field) -> void {
		auto& fieldContainer = GetFieldJsonContainer(field, true);

		auto jObject = field->ToJson();
		if (jObject.empty()) {
			RemoveFieldContainer(field, field->GetSection(), field->GetName(), field->IsShared());
		} else {
			fieldContainer = jObject;
		}
	}

	auto LoadAll() -> void {
		for (auto& entry : s_Entries)
			LoadField(entry.get());
	}

	auto OnFieldChanged(internal::FieldEntry* field) -> void {
		LoadField(field);
		Save();
	}

	auto OnFieldMoved(internal::FieldEntry* field, const std::string& oldSection, bool oldShared) -> void {
		RemoveFieldContainer(field, oldSection, field->GetName(), oldShared);
		OnFieldChanged(field);
	}

	auto OnFieldReposition(internal::FieldEntry* field, const std::string& oldSection, bool oldShared) -> void {
		field->SetContainer(nullptr);
		UpdateField(field);
	}

	auto internal::AddField(std::shared_ptr<FieldEntry> field) -> void {
		s_Entries.push_back(field);
		UpdateField(field.get());
		field->ChangedEvent += FUNCTION_HANDLER(OnFieldChanged);
		field->MovedEvent += FUNCTION_HANDLER(OnFieldMoved);
		field->RepositionEvent += FUNCTION_HANDLER(OnFieldReposition);
	}

	auto Refresh() -> void {
		LoadAll();
		Save();
	}

	auto SaveInternal() -> void {
		std::ofstream fileOutput(s_Filepath, std::ios::out);
		if (!fileOutput.is_open()) {
			LOG_DEBUG << "打开配置文件进行写入失败.";
			UpdateSaveTimestamp();
			return;
		}

		fileOutput << s_ConfigRoot.dump(4);
		fileOutput.close();
	}

	auto Save() -> void {
		if (s_UpdateEvent) {
			UpdateSaveTimestamp();
			return;
		}
		SaveInternal();
	}

	auto OnUpdate() -> void {
		if (s_NextSaveTimestamp > 0 && std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count() > s_NextSaveTimestamp) {
			s_NextSaveTimestamp = 0;
			SaveInternal();
		}
	}

	auto CreateProfile(const std::string& profileName, bool moveAfterCreate) -> void {
		if (s_Profiles->contains(profileName)) {
			if (moveAfterCreate) {
				ChangeProfile(profileName);
			}
			return;
		}

		(*s_Profiles)[profileName] = {};
		UpdateProfilesNames();

		if (moveAfterCreate) {
			ChangeProfile(profileName);
		}
		Save();
	}

	auto RemoveProfile(const std::string& profileName) -> void {
		if (!s_Profiles->contains(profileName)) {
			return;
		}

		if (s_Profiles->size() == 1) {
			return;
		}

		if (s_ProfileName == profileName) {
			for (auto& [name, value] : s_Profiles->items()) {
				if (name != profileName) {
					ChangeProfile(name);
					break;
				}
			}
		}

		s_Profiles->erase(profileName);
		UpdateProfilesNames();
		Save();
	}

	auto RenameProfile(const std::string& oldProfileName, const std::string& newProfileName) -> void {
		if (!s_Profiles->contains(oldProfileName) || s_Profiles->contains(newProfileName)) {
			return;
		}

		if (s_ProfileName == oldProfileName) {
			s_ProfileRoot = nullptr;
		}

		(*s_Profiles)[newProfileName] = (*s_Profiles)[oldProfileName];
		s_Profiles->erase(oldProfileName);

		if (s_ProfileRoot == nullptr) {
			for (auto& entry : s_Entries) {
				if (!entry->IsShared()) {
					entry->SetContainer(nullptr);
				}
			}

			ChangeProfile(newProfileName);
		}
		UpdateProfilesNames();
		Save();
	}

	auto ChangeProfile(const std::string& profileName) -> void {
		if (s_ProfileName == profileName) {
			return;
		}

		if (!s_Profiles->contains(profileName)) {
			return;
		}

		std::lock_guard _lock(s_ProfileMutex);

		s_ProfileRoot = &(*s_Profiles)[profileName];
		s_ProfileName = profileName;

		s_ConfigRoot["current_profile"] = profileName;
		UpdateNotShared();
		Save();

		ProfileChanged();
	}

	auto DuplicateProfile(const std::string& profileName) -> void {
		// Find a unique name for the new profile
		uint32_t counter = 0;
		std::ostringstream buffer;
		std::string newProfileName;
		do {
			buffer.str(std::string());
			buffer.clear();
			counter++;
			buffer << profileName << " (" << counter << ")";
			newProfileName = buffer.str();
		} while (s_Profiles->contains(newProfileName));

		// nlohmann::json copy constructor will take care of duplicating
		(*s_Profiles)[newProfileName] = (*s_Profiles)[profileName];
		UpdateProfilesNames();
		Save();
	}

	auto GetProfiles() -> const std::vector<std::string>& {
		return s_ProfilesNames;
	}

	auto CurrentProfileName() -> const std::string& {
		return s_ProfileName;
	}
}
