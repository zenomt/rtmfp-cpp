#pragma once

// Copyright © 2021 Michael Thornburgh
// SPDX-License-Identifier: MIT

namespace com { namespace zenomt { namespace rtmfp {

struct PacketAssembler {
	void init(uint8_t *buf, size_t frontMargin, size_t maxLen);
	void init(uint8_t *buf, size_t frontMargin, size_t maxLen, uint8_t flags_, long ts, long tse);
	bool startChunk(uint8_t type_);
	bool push(uint8_t byte);
	bool push(const void *bytes, size_t len);
	bool push(const std::vector<uint8_t> &bytes);
	bool pushField(const void *bytes, size_t len);
	bool pushField(const std::vector<uint8_t> &bytes);
	bool pushVLU(uintmax_t val);
	void setTimeCriticalFlag();
	bool getTimeCriticalFlag() const;
	void commitChunk();
	void rollbackChunk();
	size_t remaining() const;
	std::vector<uint8_t> toVector() const;

	uint8_t *m_buf;
	size_t   m_frontMargin;
	uint8_t *m_limit;
	uint8_t *m_currentChunkStart;
	uint8_t *m_cursor;
	uint8_t *m_flags;
};

} } } // namespace com::zenomt::rtmfp
