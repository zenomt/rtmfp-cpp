#pragma once

// Copyright © 2021 Michael Thornburgh
// SPDX-License-Identifier: MIT

// inspired by MObjList from amicima

#include <vector>

#if __cpp_exceptions
  #include <stdexcept>
#else
  #include <cstdlib>
#endif

#include "Object.hpp"

namespace com { namespace zenomt {

template <class T> class List : public Object {
public:
	static const long SENTINEL = 0;

	List(const T& blank = T());

	bool    empty()         const;
	size_t  size()          const;

	long    next(long name) const;
	long    prev(long name) const;

	bool    has(long name)  const;
	long    first()         const;
	long    last()          const;
	long    find(const T& val) const;

	T&      at(long name);
	T&      firstValue();
	T&      lastValue();

	const T& at(long name) const;

	long    addAfter(long name);
	long    addAfter(const T& val, long name);

	long    addBefore(long name);
	long    addBefore(const T& val, long name);

	long    append(const T& val);
	long    prepend(const T& val);

	bool    rotateNameToHead(long name);
	bool    rotateNameToTail(long name);
	bool    moveNameToHead(long name);
	bool    moveNameToTail(long name);

	virtual bool remove(long name);
	bool    removeFirst();
	bool    removeLast();

	void    clear();

	void    appendValuesFrom(const List<T>& other);
	bool    valuesDo(const std::function<bool(T& value)> &pred);
	bool    safeValuesDo(const std::function<bool(T& value)> &pred);


protected:
	static const long   FREELIST  = 1;
	static const size_t INIT_SIZE = 16;
	static const size_t GROW_SIZE = 16;

	void init();
	void initNewNodes(long start);
	void growFreeList();
	bool freeListEmpty() const;
	void unlinkNode(long name);
	void linkBefore(long name, long beforeName);
	void linkAfter(long name, long afterName);
	virtual long addValueBeforeOrAfter(const T& val, long name, bool after);
	long basicAddBeforeOrAfter(long name, bool after);

	struct Node {
		long  m_next;
		long  m_prev;
		T     m_val;
		bool  m_inUse;
	};

	size_t             m_size;
	std::vector<Node>  m_nodes;
	T                  m_blank;
};

template <class T> class SumList : public List<T> {
public:
	using Size_f = std::function<size_t(const T& value)>;
	SumList(const Size_f size_f, const T& blank = T());

	size_t sum() const;
	bool remove(long name) override;

protected:
	long addValueBeforeOrAfter(const T& val, long name, bool after) override;

	size_t m_sum;
	Size_f m_size_f;
};

// --- implementation List<T>

template <class T> List<T>::List(const T& blank) :
	m_size(0),
	m_nodes(),
	m_blank(blank)
{
	init();
}

template <class T> bool List<T>::empty() const
{
	return SENTINEL == m_nodes[SENTINEL].m_next;
}

template <class T> size_t List<T>::size() const
{
	return m_size;
}

template <class T> long List<T>::next(long name) const
{
	return has(name) ? m_nodes[name].m_next : -1;
}

template <class T> long List<T>::prev(long name) const
{
	return has(name) ? m_nodes[name].m_prev : -1;
}

template <class T> bool List<T>::has(long name) const
{
	return (name >= SENTINEL) && ((unsigned long)name < m_nodes.size()) && (m_nodes[name].m_inUse);
}

template <class T> long List<T>::first() const
{
	return next(SENTINEL);
}

template <class T> long List<T>::last() const
{
	return prev(SENTINEL);
}

template <class T> long List<T>::find(const T& val) const
{
	for(long name = first(); name > SENTINEL; name = next(name))
		if(at(name) == val)
			return name;

	return SENTINEL;
}

template <class T> T& List<T>::at(long name)
{
	if((not has(name)) or (SENTINEL == name))
#if __cpp_exceptions
		throw std::out_of_range("List::at range check");
#else
		abort();
#endif

	return m_nodes[name].m_val;
}

template <class T> const T& List<T>::at(long name) const
{
	if((not has(name)) or (SENTINEL == name))
#if __cpp_exceptions
		throw std::out_of_range("List::at range check");
#else
		abort();
#endif

	return m_nodes[name].m_val;
}

template <class T> T& List<T>::firstValue()
{
	return at(first());
}

template <class T> T& List<T>::lastValue()
{
	return at(last());
}

template <class T> long List<T>::addAfter(long name)
{
	return basicAddBeforeOrAfter(name, true);
}

template <class T> long List<T>::addAfter(const T& val, long name)
{
	return addValueBeforeOrAfter(val, name, true);
}

template <class T> long List<T>::addBefore(long name)
{
	return basicAddBeforeOrAfter(name, false);
}

template <class T> long List<T>::addBefore(const T& val, long name)
{
	return addValueBeforeOrAfter(val, name, false);
}

template <class T> long List<T>::append(const T& val)
{
	return addBefore(val, SENTINEL);
}

template <class T> long List<T>::prepend(const T& val)
{
	return addAfter(val, SENTINEL);
}

template <class T> bool List<T>::rotateNameToHead(long name)
{
	if(not has(name))
		return false;
	if(SENTINEL == name)
		return true;

	unlinkNode(SENTINEL);
	linkBefore(SENTINEL, name);

	return true;
}

template <class T> bool List<T>::rotateNameToTail(long name)
{
	if(not has(name))
		return false;
	if(SENTINEL == name)
		return true;

	unlinkNode(SENTINEL);
	linkAfter(SENTINEL, name);

	return true;
}

template <class T> bool List<T>::moveNameToHead(long name)
{
	if(not has(name))
		return false;
	if(SENTINEL == name)
		return true;

	unlinkNode(name);
	linkAfter(name, SENTINEL);

	return true;
}

template <class T> bool List<T>::moveNameToTail(long name)
{
	if(not has(name))
		return false;
	if(SENTINEL == name)
		return true;

	unlinkNode(name);
	linkBefore(name, SENTINEL);

	return true;
}

template <class T> bool List<T>::remove(long name)
{
	if((SENTINEL == name) or not has(name))
		return false;

	unlinkNode(name);
	m_size--;
	m_nodes[name].m_inUse = false;
	linkBefore(name, FREELIST);
	m_nodes[name].m_val = m_blank;

	return true;
}

template <class T> bool List<T>::removeFirst()
{
	return remove(first());
}

template <class T> bool List<T>::removeLast()
{
	return remove(last());
}

template <class T> void List<T>::clear()
{
	while(removeFirst());
}

template <class T> void List<T>::appendValuesFrom(const List<T>& other)
{
	for(long name = other.first(); name > SENTINEL; name = other.next(name))
		append(other.at(name));
}

template <class T> bool List<T>::valuesDo(const std::function<bool(T& value)> &pred)
{
	for(long name = first(); name > SENTINEL; name = next(name))
		if(not pred(at(name)))
			return false;
	return true;
}

template <class T> bool List<T>::safeValuesDo(const std::function<bool(T& value)> &pred)
{
	List<T> tmp;
	tmp.appendValuesFrom(*this);
	return tmp.valuesDo(pred);
}

// --- protected implementation

template <class T> void List<T>::init()
{
	m_nodes.resize(INIT_SIZE);

	m_nodes[SENTINEL].m_next = m_nodes[SENTINEL].m_prev = SENTINEL;
	m_nodes[SENTINEL].m_inUse = true;

	m_nodes[FREELIST].m_next = m_nodes[FREELIST].m_prev = FREELIST;
	m_nodes[FREELIST].m_inUse = false;

	m_nodes[SENTINEL].m_val = m_nodes[FREELIST].m_val = m_blank;
        
	initNewNodes(FREELIST + 1);
}

template <class T> void List<T>::initNewNodes(long start)
{
	long i;

	for(i = start; i < (long)m_nodes.size(); i++)
	{
		m_nodes[i].m_prev  = i - 1;
		m_nodes[i].m_next  = i + 1;
		m_nodes[i].m_val   = m_blank;
		m_nodes[i].m_inUse = false;
	}

	m_nodes[start].m_prev = m_nodes[FREELIST].m_prev;
	m_nodes[i - 1].m_next = FREELIST;
	m_nodes[m_nodes[FREELIST].m_prev].m_next = start;
	m_nodes[FREELIST].m_prev = i - 1;
}

template <class T> void List<T>::growFreeList()
{
	size_t currentSize = m_nodes.size();
	m_nodes.resize(currentSize + GROW_SIZE);
	initNewNodes((long)currentSize);
}

template <class T> bool List<T>::freeListEmpty() const
{
	return FREELIST == m_nodes[FREELIST].m_next;
}

template <class T> void List<T>::unlinkNode(long name)
{
	m_nodes[m_nodes[name].m_prev].m_next = m_nodes[name].m_next;
	m_nodes[m_nodes[name].m_next].m_prev = m_nodes[name].m_prev;
}

template <class T> void List<T>::linkBefore(long name, long beforeName)
{
	m_nodes[name].m_next = beforeName;
	m_nodes[name].m_prev = m_nodes[beforeName].m_prev;
	m_nodes[m_nodes[beforeName].m_prev].m_next = name;
	m_nodes[beforeName].m_prev = name;
}

template <class T> void List<T>::linkAfter(long name, long afterName)
{
	m_nodes[name].m_next = m_nodes[afterName].m_next;
	m_nodes[name].m_prev = afterName;
	m_nodes[m_nodes[afterName].m_next].m_prev = name;
	m_nodes[afterName].m_next = name;
}

template <class T> long List<T>::basicAddBeforeOrAfter(long name, bool after)
{
	if(not has(name))
		return -1;

	if(freeListEmpty())
		growFreeList();

	long rv = m_nodes[FREELIST].m_next;
	unlinkNode(rv);
	m_nodes[rv].m_inUse = true;

	if(after)
		linkAfter(rv, name);
	else
		linkBefore(rv, name);

	m_size++;

	return rv;
}

template <class T> long List<T>::addValueBeforeOrAfter(const T& val, long name, bool after)
{
	long rv = basicAddBeforeOrAfter(name, after);
	at(rv) = val;
	return rv;
}

// --- implementation SumList<T>

template <class T> SumList<T>::SumList(const Size_f size_f, const T& blank) :
	List<T>(blank),
	m_sum(0),
	m_size_f(size_f)
{
}

template <class T> bool SumList<T>::remove(long name)
{
	if((SumList<T>::SENTINEL == name) or not this->has(name))
		return false;

	m_sum -= m_size_f(this->at(name));
	return List<T>::remove(name);
}

template <class T> size_t SumList<T>::sum() const
{
	return m_sum;
}

template <class T> long SumList<T>::addValueBeforeOrAfter(const T& val, long name, bool after)
{
	long rv = List<T>::addValueBeforeOrAfter(val, name, after);
	m_sum += m_size_f(val);
	return rv;
}

} } // namespace com::zenomt
