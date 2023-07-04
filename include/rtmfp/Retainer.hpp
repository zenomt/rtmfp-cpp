#pragma once

// Copyright © 2023 Michael Thornburgh
// SPDX-License-Identifier: MIT

// Retainer<T> is similar to std::shared_ptr<T> but uses T's native retain()
// and release() methods instead of maintaining an external reference count.
//
// Usually a Retainer retain()s its pointer; however its constructor
// Retainer(T *ptr, bool retain) and convenience function
// claim_ref(T *ptr) can avoid the initial retain() in order to
// assume ownership of an existing (or initial) retain of ptr. For example:
//
//     Retainer<Foo> retained = Retainer<Foo>(new Foo(), false);
// -- or --
//     auto retained = claim_ref(new Foo());
//
// On destruction, a Retainer _always_ release()es its pointer.

#include <cstddef>

namespace com { namespace zenomt {

template <class T> class Retainer {
public:
	~Retainer() { _release(m_ptr); }

	constexpr Retainer() {}
	constexpr Retainer(std::nullptr_t) {}
	Retainer(T *ptr) : Retainer(ptr, true) {}
	Retainer(T *ptr, bool retain) : m_ptr(ptr) { if(retain) _retain(ptr); }
	Retainer(const Retainer &other) : Retainer(other.m_ptr, true) {}
	Retainer(Retainer &&other) : m_ptr(other.m_ptr) { other.m_ptr = nullptr; }

	template <class U> Retainer(const Retainer<U> &other) : Retainer(other.m_ptr, true) {}
	template <class U> Retainer(Retainer<U> &&other) : m_ptr(other.m_ptr) { other.m_ptr = nullptr; }

	Retainer& operator= (const Retainer &other) { basicAssign(other.m_ptr); return *this; }
	template <class U> Retainer& operator= (const Retainer<U> &other) { basicAssign(other.m_ptr); return *this; }

	Retainer& operator= (Retainer &&other)
	{
		T *tmp = m_ptr;
		m_ptr = other.m_ptr;
		other.m_ptr = nullptr;
		_release(tmp);
		return *this;
	}

	template <class U> Retainer& operator= (Retainer<U> &&other)
	{
		T *tmp = m_ptr;
		m_ptr = other.m_ptr;
		other.m_ptr = nullptr;
		_release(tmp);
		return *this;
	}

	void swap(Retainer &other)
	{
		T *tmp = m_ptr;
		m_ptr = other.m_ptr;
		other.m_ptr = tmp;
	}

	T * get() const { return m_ptr; }
	T * operator->() const { return m_ptr; }
	T & operator*() const { return *m_ptr; }

	void reset() { basicAssign(nullptr); }
	bool empty() const { return nullptr == m_ptr; }
	operator bool() const { return not empty(); }

protected:
	template <class U> friend class Retainer; // all Retainers are friends

	static inline void _retain(T *ptr) { if(ptr) ptr->retain(); }
	static inline void _release(T *ptr) { if(ptr) ptr->release(); }

	void basicAssign(T *newval)
	{
		if(m_ptr != newval)
		{
			T *tmp = m_ptr;
			m_ptr = newval;
			_retain(newval);
			_release(tmp);
		}
	}

	T *m_ptr { nullptr };
};

template <class T> Retainer<T> retain_ref(T *ptr)
{
	return Retainer<T>(ptr);
}

template <class T> Retainer<T> claim_ref(T *ptr)
{
	return Retainer<T>(ptr, false);
}

template <class T, class U> bool operator== (const Retainer<T> &lhs, const Retainer<U> &rhs) { return lhs.get() == rhs.get(); }
template <class T> bool operator== (const Retainer<T> &lhs, std::nullptr_t) { return lhs.empty(); }
template <class T> bool operator== (std::nullptr_t, const Retainer<T> &rhs) { return rhs.empty(); }

template <class T, class U> bool operator!= (const Retainer<T> &lhs, const Retainer<U> &rhs) { return not (lhs == rhs); }
template <class T> bool operator!= (const Retainer<T> &lhs, std::nullptr_t) { return lhs; }
template <class T> bool operator!= (std::nullptr_t, const Retainer<T> &rhs) { return rhs; }

template <class T, class U> bool operator< (const Retainer<T> &lhs, const Retainer<U> &rhs) { return lhs.get() < rhs.get(); }
template <class T> bool operator< (const Retainer<T> &lhs, std::nullptr_t) { return false; }
template <class T> bool operator< (std::nullptr_t, const Retainer<T> &rhs) { return rhs; }

template <class T, class U> bool operator> (const Retainer<T> &lhs, const Retainer<U> &rhs) { return rhs < lhs; }
template <class T> bool operator> (const Retainer<T> &lhs, std::nullptr_t) { return lhs; }
template <class T> bool operator> (std::nullptr_t, const Retainer<T> &rhs) { return false; }

template <class T, class U> bool operator>= (const Retainer<T> &lhs, const Retainer<U> &rhs) { return not (lhs < rhs); }
template <class T> bool operator>= (const Retainer<T> &lhs, std::nullptr_t) { return true; }
template <class T> bool operator>= (std::nullptr_t, const Retainer<T> &rhs) { return rhs.empty(); }

template <class T, class U> bool operator<= (const Retainer<T> &lhs, const Retainer<U> &rhs) { return not (rhs < lhs); }
template <class T> bool operator<= (const Retainer<T> &lhs, std::nullptr_t) { return lhs.empty(); }
template <class T> bool operator<= (std::nullptr_t, const Retainer<T> &rhs) { return true; }

} } // namespace com::zenomt
