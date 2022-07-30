// Copyright © 2021 Michael Thornburgh
// SPDX-License-Identifier: MIT

#include <cstring>

#include "../include/rtmfp/rtmfp.hpp"
#include "../include/rtmfp/packet.hpp"
#include "../include/rtmfp/VLU.hpp"
#include "../include/rtmfp/PacketAssembler.hpp"

namespace com { namespace zenomt { namespace rtmfp {

void PacketAssembler::init(uint8_t *buf, size_t frontMargin, size_t maxLen)
{
	m_buf = buf;
	m_frontMargin = frontMargin;
	m_limit = m_buf + maxLen;
	m_cursor = buf + frontMargin;
	m_currentChunkStart = nullptr;
	m_flags = nullptr;
}

void PacketAssembler::init(uint8_t *buf, size_t frontMargin, size_t maxLen, uint8_t flags_, long ts, long tse)
{
	init(buf, frontMargin, maxLen);

	uint8_t flags = flags_ & ~(HEADER_FLAG_TS | HEADER_FLAG_TSE);
	if(ts >= 0)
		flags |= HEADER_FLAG_TS;
	if(tse >= 0)
		flags |= HEADER_FLAG_TSE;

	m_flags = m_cursor++;
	*m_flags = flags;

	if(ts >= 0)
	{
		*m_cursor++ = (ts >> 8) & 0xff;
		*m_cursor++ = ts & 0xff;
	}
	if(tse >= 0)
	{
		*m_cursor++ = (tse >> 8) & 0xff;
		*m_cursor++ = tse & 0xff;
	}
}

bool PacketAssembler::startChunk(uint8_t type_)
{
	if(remaining() < 3)
		return false;

	*m_cursor++ = type_;
	*m_cursor++ = 0;
	*m_cursor++ = 0;
	m_currentChunkStart = m_cursor;

	return true;
}

bool PacketAssembler::push(uint8_t byte)
{
	if(remaining() < 1)
		return false;
	*m_cursor++ = byte;
	return true;
}

bool PacketAssembler::push(const void *bytes, size_t len)
{
	if(remaining() < len)
		return false;

	memmove(m_cursor, bytes, len);
	m_cursor += len;

	return true;
}

bool PacketAssembler::push(const std::vector<uint8_t> &bytes)
{
	return push(bytes.data(), bytes.size());
}

bool PacketAssembler::pushField(const void *bytes, size_t len)
{
	uint8_t *savedCursor = m_cursor;

	if(pushVLU(len) and push(bytes, len))
		return true;

	m_cursor = savedCursor;
	return false;
}

bool PacketAssembler::pushField(const std::vector<uint8_t> &bytes)
{
	return pushField(bytes.data(), bytes.size());
}

bool PacketAssembler::pushVLU(uintmax_t val)
{
	uint8_t vlu[VLU::MAX_VLU_SIZE];
	size_t rv = VLU::encode(val, vlu);
	return push(vlu, rv);
}

void PacketAssembler::setTimeCriticalFlag()
{
	*m_flags |= HEADER_FLAG_TC;
}

bool PacketAssembler::getTimeCriticalFlag() const
{
	return *m_flags & HEADER_FLAG_TC;
}

void PacketAssembler::commitChunk()
{
	size_t chunkLength = m_cursor - m_currentChunkStart;
	*(m_currentChunkStart - 2) = (chunkLength >> 8) & 0xff;
	*(m_currentChunkStart - 1) = chunkLength & 0xff;
	m_currentChunkStart = nullptr;
}

void PacketAssembler::rollbackChunk()
{
	if(m_currentChunkStart)
	{
		m_cursor = m_currentChunkStart - 3;
		m_currentChunkStart = nullptr;
	}
}

size_t PacketAssembler::remaining() const
{
	return m_limit - m_cursor;
}

std::vector<uint8_t> PacketAssembler::toVector() const
{
	return std::vector<uint8_t>(m_buf, m_cursor);
}

} } } // namespace com::zenomt::rtmfp
