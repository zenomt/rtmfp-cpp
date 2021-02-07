#pragma once

// Copyright © 2021 Michael Thornburgh
// SPDX-License-Identifier: MIT

#include <string>
#include <vector>

namespace com { namespace zenomt {

class Hex {
public:
	static void print(const char *msg, const void *bytes, const void *limit);
	static void print(const char *msg, const void *bytes, size_t len);

	static void dump(const char *msg, const void *bytes, const void *limit, bool nl = true);
	static void dump(const char *msg, const void *bytes, size_t len, bool nl = true);

	static std::string encode(const void *bytes, size_t len);
	static std::string encode(const void *bytes, const void *limit);

	static bool decode(const char *hex, std::vector<uint8_t> &dst);
};

} } // namespace com::zenomt
