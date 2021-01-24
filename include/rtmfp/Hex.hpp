#pragma once

// Copyright © 2021 Michael Thornburgh
// SPDX-License-Identifier: MIT

namespace com { namespace zenomt {

class Hex {
public:
	static void print(const char *msg, const void *bytes, const void *limit);
	static void print(const char *msg, const void *bytes, size_t len);

	static void dump(const char *msg, const void *bytes, const void *limit, bool nl = true);
	static void dump(const char *msg, const void *bytes, size_t len, bool nl = true);
};

} } // namespace com::zenomt
