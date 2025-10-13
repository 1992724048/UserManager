#pragma once
#include <string>
#include "../events/event.hpp"
#include "../json.hpp"

namespace config::internal
{
	class FieldEntry
	{
	public:
		FieldEntry(const std::string& friendlyName, const std::string& name, const std::string& sectionName, const bool multiProfile = false)
			: m_Name(name), m_FriendName(friendlyName), m_Section(sectionName), m_MultiProfile(multiProfile), m_Container(nullptr) {}

		TEvent<FieldEntry*> ChangedEvent;
		TEvent<FieldEntry*, const std::string&, bool> MovedEvent;
		TEvent<FieldEntry*, const std::string&, bool> RepositionEvent;

		virtual void FireChanged()
		{
			ChangedEvent(this);
		}

		virtual nlohmann::json ToJson() = 0;
		virtual void FromJson(const nlohmann::json& value) = 0;
		virtual void Reset() = 0;

		bool IsShared() const
		{
			return m_MultiProfile;
		}

		std::string GetName() const
		{
			return m_Name;
		}

		std::string GetFriendName() const
		{
			return m_FriendName;
		}

		std::string GetSection() const
		{
			return m_Section;
		}

		nlohmann::json* GetContainer() const
		{
			return m_Container;
		}

		void Reposition(const std::string& newSection, bool shared = false)
		{
			std::string oldSection = m_Section;

			m_Section = newSection;
			m_MultiProfile = shared;

			RepositionEvent(this, newSection, shared);
		}

		void Move(const std::string& newSection, bool shared = false)
		{
			std::string oldSection = m_Section;
			bool oldMultiProfile = m_MultiProfile;

			m_Section = newSection;
			m_MultiProfile = shared;

			MovedEvent(this, oldSection, oldMultiProfile);
		}

		void SetContainer(nlohmann::json* newContainer)
		{
			m_Container = nullptr;
		}

	protected:
		std::string m_Name;
		std::string m_FriendName;
		std::string m_Section;
		bool m_MultiProfile;

		nlohmann::json* m_Container;
	};
}