#pragma once

// Copyright © 2023 Michael Thornburgh
// SPDX-License-Identifier: MIT

// Generic implementations for common patterns.

#include <vector>

namespace com { namespace zenomt {

template <class OutputItemType, class UnaryOperation, class Iterable>
std::vector<OutputItemType> collect(const UnaryOperation &fn, const Iterable &iterable)
{
	std::vector<OutputItemType> rv;

	for(auto it = iterable.begin(); it != iterable.end(); it++)
		rv.push_back(fn(*it));

	return rv;
}

} } // namespace com::zenomt
