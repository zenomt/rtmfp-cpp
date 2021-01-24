// Copyright © 2021 Michael Thornburgh
// SPDX-License-Identifier: MIT

#include "../include/rtmfp/IndexSet.hpp"

// inspired by MObjIndexSet from amicima

namespace com { namespace zenomt {

// --- Range

Range::Range() : start(0), end(0) {}

Range::Range(uintmax_t fromIndex, uintmax_t toIndex) :
	start(fromIndex),
	end(toIndex)
{
}

uintmax_t Range::size() const
{
	uintmax_t rv = end - start;
	rv++;

	if(0 == rv)
		rv--;

	return rv;
}

bool Range::intersects(uintmax_t fromIndex, uintmax_t toIndex) const
{
	return (fromIndex <= end) and (toIndex >= start);
}

bool Range::intersects(const Range& other) const
{
	return intersects(other.start, other.end);
}

bool Range::contiguousWith(uintmax_t fromIndex, uintmax_t toIndex) const
{
	if(fromIndex > 0)
		fromIndex--;
	if(toIndex < toIndex + 1)
		toIndex++;

	return intersects(fromIndex, toIndex);
}

bool Range::contiguousWith(const Range& other) const
{
	return contiguousWith(other.start, other.end);
}

bool Range::contains(uintmax_t fromIndex, uintmax_t toIndex) const
{
	return (fromIndex >= start) and (toIndex <= end);
}

bool Range::contains(uintmax_t anIndex) const
{
	return contains(anIndex, anIndex);
}

bool Range::contains(const Range& other) const
{
	return contains(other.start, other.end);
}

void Range::extend(uintmax_t fromIndex, uintmax_t toIndex)
{
	if(fromIndex <= toIndex)
	{
		if(fromIndex < start)
			start = fromIndex;

		if(toIndex > end)
			end = toIndex;
	}
}

void Range::extend(const Range& other)
{
	extend(other.start, other.end);
}

// --- IndexSet

IndexSet::IndexSet(const IndexSet &other) :
	m_ranges(other.m_ranges)
{
}

uintmax_t IndexSet::size() const
{
	uintmax_t rv = 0;
	rangesDo([&] (const Range& eachRange) { rv += eachRange.size(); return true; });
	return rv;
}

size_t IndexSet::countRanges() const
{
	return m_ranges.size();
}

bool IndexSet::empty() const
{
	return m_ranges.empty();
}

bool IndexSet::contains(uintmax_t anIndex) const
{
	return not rangesDo([&] (const Range& each) { return not each.contains(anIndex); });
}

uintmax_t IndexSet::lowestIndex() const
{
	return empty() ? 0 : m_ranges.front().start;
}

uintmax_t IndexSet::highestIndex() const
{
	return empty() ? 0 : m_ranges.back().end;
}

Range IndexSet::firstRange() const
{
	return empty() ? Range() : m_ranges.front();
}

Range IndexSet::lastRange() const
{
	return empty() ? Range() : m_ranges.back();
}

bool IndexSet::rangesDo(const std::function<bool(const Range& eachRange)> &each_f) const
{
	for(auto it = m_ranges.cbegin(); it != m_ranges.cend(); it++)
	{
		if(not each_f(*it))
			return false;
	}
	return true;
}

bool IndexSet::extentsDo(const std::function<bool(uintmax_t fromIndex, uintmax_t toIndex)> &each_f) const
{
	return rangesDo([&] (const Range& eachRange) { return each_f(eachRange.start, eachRange.end); });
}

bool IndexSet::indicesDo(const std::function<bool(uintmax_t eachIndex)> &each_f) const
{
	return extentsDo([&] (uintmax_t fromIndex, uintmax_t toIndex) {
		for(uintmax_t eachIndex = fromIndex; eachIndex <= toIndex; eachIndex++)
		{
			if(not each_f(eachIndex))
				return false;
		}
		return true;
	});
}

void IndexSet::add(uintmax_t fromIndex, uintmax_t toIndex)
{
	if(toIndex < fromIndex)
		return;

	auto each = m_ranges.begin();
	while(each != m_ranges.end())
	{
		if(each->contiguousWith(fromIndex, toIndex))
		{
			each->extend(fromIndex, toIndex);

			auto mergeEach = each;
			while(++mergeEach != m_ranges.end())
			{
				if(each->contiguousWith(*mergeEach))
				{
					each->extend(*mergeEach);
					m_ranges.erase(mergeEach);
					mergeEach = each;
				}
				else
					return;
			}

			return;
		}

		if(each->start > toIndex)
			break; // insert a new range right before each

		each++;
	}

	// at this point, each is pointing to the spot in the ranges list
	// before which a new Range must be inserted, either because we ran out
	// (each == end), or the range that's there is after from..to.

	m_ranges.insert(each, Range(fromIndex, toIndex));
}

void IndexSet::add(uintmax_t anIndex)
{
	return add(anIndex, anIndex);
}

void IndexSet::add(const IndexSet& other)
{
	other.extentsDo([&] (uintmax_t fromIndex, uintmax_t toIndex) { add(fromIndex, toIndex); return true; });
}

void IndexSet::remove(uintmax_t fromIndex, uintmax_t toIndex)
{
	if(toIndex < fromIndex)
		return;

	auto each = m_ranges.begin();
	while(each != m_ranges.end())
	{
		if(toIndex < each->start)
			return; // all done

		if(not each->intersects(fromIndex, toIndex))
		{
			each++;
			continue; // nothing to do here, advance to next range
		}

		if(each->start < fromIndex)
		{
			if(toIndex < each->end)
			{
				// this case is the "remove a hole from the middle of the range" one
				m_ranges.insert(each, Range(each->start, fromIndex - 1));
				each->start = toIndex + 1;

				// remove-range was entirely contained by each, so we're done.
				return;
			}

			// otherwise this range's end is in the intersection, so shorten it.
			each->end = fromIndex - 1;
			each++; // advance to next range
		}
		else
		{
			if(toIndex < each->end)
			{
				each->start = toIndex + 1;
				return; // after this, the remove range is exhausted
			}
			else
			{
				// this case is the "from..to covers this entire range" one, so remove it (and advance).
				each = m_ranges.erase(each);
			}
		}
	}
}

void IndexSet::remove(uintmax_t anIndex)
{
	return remove(anIndex, anIndex);
}

void IndexSet::remove(const IndexSet& other)
{
	other.extentsDo([&] (uintmax_t fromIndex, uintmax_t toIndex) { remove(fromIndex, toIndex); return true; });
}

void IndexSet::clear()
{
	m_ranges.clear();
}

} } // namespace com::zenomt
