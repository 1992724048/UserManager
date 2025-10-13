#pragma once

#include "../events/event.hpp"
#include "FieldEntry.h"
#include "FieldSerialize.h"

namespace config::internal {
	template <typename T>
	class FieldBase {
		using _FieldBaseT = FieldBase<T>;

	public:
		using _ValueType = T;

		explicit FieldBase() : FieldChangedEvent(m_FieldChangedEvent), p_Container(nullptr) {}

		explicit FieldBase(FieldSerialize<T>* serializeFieldPtr) : FieldChangedEvent(m_FieldChangedEvent), p_Container(serializeFieldPtr) { p_Container->ChangedEvent += MY_METHOD_HANDLER(_FieldBaseT::OnFieldChanged); }

		explicit FieldBase(const std::shared_ptr<FieldSerialize<T>>& serializeField) : FieldChangedEvent(m_FieldChangedEvent), p_Container(serializeField) { p_Container->ChangedEvent += MY_METHOD_HANDLER(_FieldBaseT::OnFieldChanged); }

		explicit FieldBase(const std::string& friendlyName, const std::string& name, const std::string& section, T defaultValue, bool multiProfile = false) : FieldChangedEvent(m_FieldChangedEvent), p_Container(std::make_shared<FieldSerialize<T>>(friendlyName, name, section, defaultValue, multiProfile)) { p_Container->ChangedEvent += MY_METHOD_HANDLER(_FieldBaseT::OnFieldChanged); }

		explicit FieldBase(const FieldBase<T>& field) : FieldChangedEvent(m_FieldChangedEvent), m_FieldChangedEvent(), p_Container(field.p_Container) { p_Container->ChangedEvent += MY_METHOD_HANDLER(FieldBase<T>::OnFieldChanged); }

		~FieldBase() { if (p_Container.get() != nullptr) { p_Container->ChangedEvent -= MY_METHOD_HANDLER(FieldBase<T>::OnFieldChanged); } }

		auto name() const -> std::string { return p_Container->GetName(); }

		auto friendName() const -> std::string { return p_Container->GetFriendName(); }

		auto section() const -> std::string { return p_Container->GetSection(); }

		auto shared() const -> bool { return p_Container->IsShared(); }

		auto value() const -> T& { return p_Container->m_Value; }

		auto pointer() const -> T* { return &p_Container->m_Value; }

		auto entry() const -> std::shared_ptr<FieldEntry> { return std::static_pointer_cast<FieldEntry>(p_Container); }

		operator T&() const { return value(); }

		operator T*() const { return pointer(); }

		auto FireChanged() const -> void { p_Container->FireChanged(); }

		auto repos(const std::string& newSection, bool shared = false) -> void { p_Container->Reposition(newSection, shared); }

		auto move(const std::string& newSection, bool shared = false) -> void { p_Container->Move(newSection, shared); }

		auto operator=(const T& other) -> FieldBase<T>& {
			p_Container->m_Value = other;
			p_Container->FireChanged();
			return *this;
		}

		auto operator=(T&& other) -> FieldBase<T>& {
			p_Container->m_Value = std::move(other);
			p_Container->FireChanged();
			return *this;
		}

		auto operator=(std::shared_ptr<FieldSerialize<T>>& other) -> FieldBase<T>& {
			p_Container->ChangedEvent -= MY_METHOD_HANDLER(FieldBase<T>::OnFieldChanged);

			p_Container = other;
			p_Container->ChangedEvent += MY_METHOD_HANDLER(FieldBase<T>::OnFieldChanged);
			return *this;
		}

		auto operator=(FieldSerialize<T>* other) -> FieldBase<T>& {
			p_Container->ChangedEvent -= MY_METHOD_HANDLER(FieldBase<T>::OnFieldChanged);

			p_Container = std::make_shared<FieldSerialize<T>>(other);
			p_Container->ChangedEvent += MY_METHOD_HANDLER(FieldBase<T>::OnFieldChanged);
			return *this;
		}

		auto operator=(const FieldBase<T>& other) -> FieldBase<T>& {
			p_Container = other.p_Container;
			p_Container->ChangedEvent += MY_METHOD_HANDLER(FieldBase<T>::OnFieldChanged);
			return *this;
		}

		IEvent<T&>& FieldChangedEvent;

	protected:
		TEvent<T&> m_FieldChangedEvent;

		std::shared_ptr<FieldSerialize<T>> p_Container;
		auto OnFieldChanged(FieldEntry* entry) -> void { m_FieldChangedEvent(value()); }
	};
}
