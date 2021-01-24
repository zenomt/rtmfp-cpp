#pragma once

// Copyright © 2021 Michael Thornburgh
// SPDX-License-Identifier: MIT

#include <cstddef>
#include <cstdint>

namespace com { namespace zenomt {

// incremental CRC-32, answer current state of shift register. final answer is typically inverted.

uint32_t crc32_le(uint32_t crc, const void *buf, size_t len); // little-endian
uint32_t crc32_le(const void *buf, size_t len); // little-endian, initialize register with 0xFFFFFFFF

uint32_t crc32_be(uint32_t crc, const void *buf, size_t len); // big-endian
uint32_t crc32_be(const void *buf, size_t len); // big-endian, initialize register with 0xFFFFFFFF

// Internet Checksum
uint16_t in_cksum(const void *buf, size_t len);

} } // namespace com::zenomt
