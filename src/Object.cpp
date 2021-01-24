// Copyright © 2021 Michael Thornburgh
// SPDX-License-Identifier: MIT

#include "../include/rtmfp/Object.hpp"

#if(DEBUG_REFCOUNT)
#include <cstdio>
#endif

namespace com { namespace zenomt {

Object::Object() : m_refcount(1) {}

Object::~Object()
{
#if(DEBUG_REFCOUNT)
	printf("delete %p\n", (void *)this);
#endif
}

void Object::retain()
{
	m_refcount++;

#if(DEBUG_REFCOUNT)
	printf("retain %ld %p\n", m_refcount + 0, (void *)this);
#endif
}

void Object::release()
{
#if(DEBUG_REFCOUNT)
	printf("release %ld %p\n", m_refcount - 1, (void *)this);
#endif

	if(0 == --m_refcount)
		delete this;
}

void Object::retain(Object *obj)
{
	if(obj)
		obj->retain();
}

void Object::release(Object *obj)
{
	if(obj)
		obj->release();
}

} } // namespace com::zenomt
