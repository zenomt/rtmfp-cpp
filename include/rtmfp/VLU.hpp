#pragma once

// Copyright © 2021 Michael Thornburgh
// SPDX-License-Identifier: MIT

#include <cstdint>
#include <cstdlib>
#include <vector>

namespace com { namespace zenomt { namespace rtmfp {

class VLU {
public:
	static const size_t MAX_VLU_SIZE = ((sizeof(uintmax_t) * 8) + 7) / 7;

	static size_t encode(uintmax_t val, void *dst);
	static void   append(uintmax_t val, std::vector<uint8_t> &dst);

	static size_t parse(const uint8_t *src, const uint8_t *limit, uintmax_t *val, bool saturate = true);
	static size_t parseField(const uint8_t *src, const uint8_t *limit, const uint8_t **payload, size_t *payloadLen);

};

class Option {
public:
	static size_t parse(const uint8_t *src, const uint8_t *limit, uintmax_t *type_, const uint8_t **value, size_t *valueLen);
	static void   append(uintmax_t type_, const void *value, size_t valueLen, std::vector<uint8_t> &dst);
	static void   append(uintmax_t type_, uintmax_t value, std::vector<uint8_t> &dst);
	static void   append(uintmax_t type_, std::vector<uint8_t> &dst);
	static void   append(std::vector<uint8_t> &dst);
};

} } } // namespace com::zenomt::rtmfp
