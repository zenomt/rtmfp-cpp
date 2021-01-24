#pragma once

// Copyright © 2021 Michael Thornburgh
// SPDX-License-Identifier: MIT

#include <atomic>
#include <functional>
#include <memory>

namespace com { namespace zenomt {

class Object {
public:
	Object();
	virtual ~Object();

	virtual void retain();
	virtual void release();

	static void retain(Object *obj);
	static void release(Object *obj);

	// Objects are intended to be reference counted and used by pointer,
	// so disable the default copy constructor. this should cause
	// a compile-time error on inappropriate usage.
	Object(const Object&) = delete;

protected:
	std::atomic_long m_refcount;
};

template <class T> std::shared_ptr<T> share_ref(T *obj, bool retain = true)
{
	if(retain)
		Object::retain(obj);
	return std::shared_ptr<T>(obj, [] (Object *p) { Object::release(p); });
}

template <class T> struct deref_less {
	bool operator() (const T& l, const T& r) const
	{
		if(r and not l)
			return true;
		if(not r)
			return false;
		return *l < *r;
	}
};

using Task = std::function<void(void)>;

} } // namespace com::zenomt
