#pragma once

// Copyright © 2021 Michael Thornburgh
// SPDX-License-Identifier: MIT

#include <cstdint>
#include <list>

#include "Object.hpp"

namespace com { namespace zenomt {

struct Range {
	Range();
	Range(uintmax_t fromIndex, uintmax_t toIndex);

	uintmax_t size() const;

	bool intersects(uintmax_t fromIndex, uintmax_t toIndex) const;
	bool intersects(const Range& other) const;

	bool contiguousWith(uintmax_t fromIndex, uintmax_t toIndex) const;
	bool contiguousWith(const Range& other) const;

	bool contains(uintmax_t fromIndex, uintmax_t toIndex) const;
	bool contains(uintmax_t anIndex) const;
	bool contains(const Range& other) const;

	void extend(uintmax_t fromIndex, uintmax_t toIndex);
	void extend(const Range& other);

	uintmax_t start;
	uintmax_t end;
};

class IndexSet : public Object {
public:
	IndexSet() = default;
	IndexSet(const IndexSet &other);

	uintmax_t size() const;
	size_t    countRanges() const;
	bool      empty() const;
	bool      contains(uintmax_t anIndex) const;
	uintmax_t lowestIndex() const;
	uintmax_t highestIndex() const;
	Range     firstRange() const;
	Range     lastRange() const;

	bool extentsDo(const std::function<bool(uintmax_t fromIndex, uintmax_t toIndex)> &each_f) const;
	bool indicesDo(const std::function<bool(uintmax_t eachIndex)> &each_f) const;

	void add(uintmax_t fromIndex, uintmax_t toIndex);
	void add(uintmax_t anIndex);
	void add(const IndexSet& other);

	void remove(uintmax_t fromIndex, uintmax_t toIndex);
	void remove(uintmax_t anIndex);
	void remove(const IndexSet& other);

	void clear();

protected:
	bool rangesDo(const std::function<bool(const Range& eachRange)> &each_f) const;

	std::list<Range> m_ranges;
};

} } // namespace com::zenomt
