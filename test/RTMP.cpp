// Copyright © 2021 Michael Thornburgh
// SPDX-License-Identifier: MIT

#include <cassert>
#include <cstring>

#include "RTMP.hpp"
#include "rtmfp/TCMessage.hpp"

namespace com { namespace zenomt { namespace rtmp {

static const size_t INITIAL_SEND_CHUNK_SIZE = 2048;

static uint32_t _readu24(const uint8_t *cursor)
{
	uint32_t rv = *cursor++;
	rv <<= 8; rv += *cursor++;
	rv <<= 8; rv += *cursor;

	return rv;
}

static uint32_t _readu32(const uint8_t *cursor)
{
	uint32_t rv = *cursor++;
	rv <<= 8; rv += *cursor++;
	rv <<= 8; rv += *cursor++;
	rv <<= 8; rv += *cursor;

	return rv;
}

static void _pushu24(RTMP::Bytes &dst, uint32_t val)
{
	dst.push_back((val >> 16) & 0xff);
	dst.push_back((val >>  8) & 0xff);
	dst.push_back((val      ) & 0xff);
}

static void _pushu32(RTMP::Bytes &dst, uint32_t val)
{
	dst.push_back((val >> 24) & 0xff);
	dst.push_back((val >> 16) & 0xff);
	dst.push_back((val >>  8) & 0xff);
	dst.push_back((val      ) & 0xff);
}

static void _pushu32le(RTMP::Bytes &dst, uint32_t val)
{
	dst.push_back((val      ) & 0xff);
	dst.push_back((val >>  8) & 0xff);
	dst.push_back((val >> 16) & 0xff);
	dst.push_back((val >> 24) & 0xff);
}

static void _setu32(uint8_t *dst, size_t val)
{
	dst[0] = (val >> 24) & 0xff;
	dst[1] = (val >> 16) & 0xff;
	dst[2] = (val >>  8) & 0xff;
	dst[3] = (val      ) & 0xff;
}

static void _pushChunkBasicHeader(RTMP::Bytes &dst, uint8_t chunkType, int chunkStreamID)
{
	if(chunkStreamID > 319)
	{
		int extendedChunkStreamID = chunkStreamID - 64;
		dst.push_back(chunkType | 1);

		// spec mismatch, Adobe sends little-endian, spec implies big-endian :(
		dst.push_back((extendedChunkStreamID     ) & 0xff);
		dst.push_back((extendedChunkStreamID >> 8) & 0xff);
	}
	else if(chunkStreamID > 63)
	{
		int extendedChunkStreamID = chunkStreamID - 64;
		dst.push_back(chunkType | 0);
		dst.push_back(extendedChunkStreamID & 0xff);
	}
	else
		dst.push_back(chunkType | (chunkStreamID & 0x3f));
}

RTMP::ChunkStreamState::ChunkStreamState() :
	m_streamID(0),
	m_timestamp(0),
	m_timestampDelta(0),
	m_length(0),
	m_type(0),
	m_initted(false),
	m_timestampDeltaValid(false)
{}

RTMP::SendChunkStreamState::SendChunkStreamState() :
	m_lastUsed(-INFINITY),
	m_busy(false)
{}

struct RTMP::Message : public Object {
	Message(uint32_t streamID, uint8_t messageType, uint32_t timestamp, const void *payload, size_t len, const std::shared_ptr<IssuerWriteReceipt> &receipt) :
		m_streamID(streamID),
		m_messageType(messageType),
		m_timestamp(timestamp),
		m_offset(0),
		m_chunkStream(-1),
		m_payload((const uint8_t *)payload, (const uint8_t *)payload + len),
		m_receipt(receipt)
	{}

	uint32_t m_streamID;
	uint8_t  m_messageType;
	uint32_t m_timestamp;
	size_t   m_offset;
	int      m_chunkStream;
	Bytes    m_payload;
	std::shared_ptr<IssuerWriteReceipt> m_receipt;
};

// --- public methods

RTMP::RTMP(IPlatformAdapter *platform) :
	m_platform(platform),
	m_state(RT_UNKNOWN),
	m_isServer(false),
	m_simpleMode(false),
	m_epoch(-INFINITY),
	m_writeScheduled(false),
	m_sendChunkSize(INITIAL_SEND_CHUNK_SIZE),
	m_recvChunkSize(DEFAULT_CHUNK_SIZE),
	m_sentBytes(0),
	m_receivedBytes(0),
	m_windowAckSize(65536),
	m_lastAckSent(0),
	m_lastAckReceived(0),
	m_peerBandwidth((size_t)-1),
	m_lastPeerBandwidthType(TC_SET_PEER_BW_LIMIT_SOFT)
{
}

bool RTMP::init(bool isServer)
{
	if(m_state > RT_UNKNOWN)
		return false;

	m_epoch = getCurrentTime();
	m_isServer = isServer;
	m_state = RT_UNINITIALIZED;

	if(not isServer)
		queueHandshake01();

	return true;
}

void RTMP::setChunkSize(size_t newSize)
{
	if(m_state > RT_OPEN)
		return; // sorry, too late!

	if(newSize < DEFAULT_CHUNK_SIZE)
		newSize = DEFAULT_CHUNK_SIZE;
	if(newSize > (size_t)(INT32_MAX))
		newSize = INT32_MAX; // §5.4.1

	if(newSize != m_sendChunkSize)
	{
		m_sendChunkSize = newSize;
		if(RT_OPEN == m_state)
			queueSetChunkSize(); // this can wait to go until the next time we actually need to write something
	}
}

size_t RTMP::getChunkSize() const
{
	return m_sendChunkSize;
}

std::shared_ptr<WriteReceipt> RTMP::write(Priority pri, uint32_t streamID, uint8_t messageType, uint32_t timestamp, const void *payload, size_t len, Time startWithin, Time finishWithin)
{
	if(m_state >= RT_CLOSING)
		return std::shared_ptr<WriteReceipt>();

	switch(messageType)
	{
	case TCMSG_SET_CHUNK_SIZE:
	case TCMSG_ABORT_MESSAGE:
	case TCMSG_ACKNOWLEDGEMENT:
	case TCMSG_WINDOW_ACK_SIZE:
	case TCMSG_SET_PEER_BW:
		// not allowed to write protocol control messages directly
		return std::shared_ptr<WriteReceipt>();
	}

	auto receipt = share_ref(new IssuerWriteReceipt(getCurrentTime(), startWithin, finishWithin), false);
	auto message = share_ref(new Message(streamID, messageType, timestamp, payload, len, receipt), false);
	receipt->useCountUp();

	m_sendQueues[pri].append(message);

	if(RT_OPEN == m_state)
		scheduleWrite();

	return receipt;
}

std::shared_ptr<WriteReceipt> RTMP::write(Priority pri, uint32_t streamID, uint8_t messageType, uint32_t timestamp, const Bytes &payload, Time startWithin, Time finishWithin)
{
	return write(pri, streamID, messageType, timestamp, payload.data(), payload.size(), startWithin, finishWithin);
}

Time RTMP::getUnsentAge(Priority pri) const
{
	return -1; // XXX
}

Time RTMP::getUnstartedAge(Priority pri) const
{
	return -1; // XXX
}

Time RTMP::getInstanceAge() const
{
	return getCurrentTime() - m_epoch;
}

Time RTMP::getCurrentTime() const
{
	return m_platform->getCurrentTime();
}

uint32_t RTMP::timeAsTimestamp(Time t) const
{
	return ((uintmax_t)(t * 1000.0)) & UINT32_MAX;
}

void RTMP::close()
{
	clearCallbacks();

	if(RT_OPEN == m_state)
	{
		m_state = RT_CLOSING;
		scheduleWrite();
	}
	else if(RT_CLOSING == m_state)
		; // already here
	else
		setClosedState();
}

void RTMP::setSimpleMode(bool isSimple)
{
	m_simpleMode = isSimple;
}

bool RTMP::onReceiveBytes(const void *bytes_, size_t len)
{
	if((RT_UNKNOWN == m_state) or (RT_PROTOCOL_ERROR == m_state))
		return false;

	m_receivedBytes += len;

	// TODO there's an opportunity to avoid a copy when the input buffer is empty
	const uint8_t *bytes = (const uint8_t *)bytes_;
	m_inputBuffer.insert(m_inputBuffer.end(), bytes, bytes + len);

	const uint8_t *buffer = m_inputBuffer.data();
	const uint8_t *limit = buffer + m_inputBuffer.size();
	const uint8_t *cursor = buffer;

	while(cursor < limit)
	{
		long consumed = onInput(cursor, limit);
		if(consumed < 0)
		{
			setClosedState();
			return false;
		}
		if(0 == consumed)
			break;
		cursor += consumed;
	}

	sendAckIfNeeded();

	shiftInputBuffer(cursor - buffer);
	return true;
}

void RTMP::onInterfaceDidClose()
{
	setClosedState();
}

// ---

bool RTMP::writeRawOutputBuffer()
{
	if((not m_rawOutputBuffer.empty()) and (m_state < RT_PROTOCOL_ERROR))
	{
		m_platform->writeBytes(m_rawOutputBuffer.data(), m_rawOutputBuffer.size());
		m_sentBytes += m_rawOutputBuffer.size();
		m_rawOutputBuffer.clear();
		return true;
	}
	return false;
}

size_t RTMP::queueStartChunk(int chunkStreamID, uint32_t streamID, uint8_t type_, uint32_t timestamp, const uint8_t *payload, size_t len)
{
	assert(chunkStreamID >= 2);
	assert(chunkStreamID < NUM_CHUNKSTREAMS);

	uint8_t chunkType = CHUNK_TYPE_0; // default
	auto &cs = m_sendChunkStreams[chunkStreamID];
	if(cs.m_initted and (timestamp - cs.m_timestamp <= (uint32_t)(INT32_MAX)) and not m_simpleMode)
	{
		// maybe we can use a more compact chunk type
		if(streamID == cs.m_streamID)
		{
			chunkType = CHUNK_TYPE_1;
			if((type_ == cs.m_type) and (len == cs.m_length))
			{
				chunkType = CHUNK_TYPE_2;
				if(cs.m_timestampDeltaValid and (timestamp == cs.m_timestamp + cs.m_timestampDelta))
					chunkType = CHUNK_TYPE_3;
			}
		}
	}

	uint32_t effectiveTimestamp = (CHUNK_TYPE_0 == chunkType) ? timestamp : timestamp - cs.m_timestamp;
	uint32_t extendedTimestamp = (effectiveTimestamp >= UINT32_C(0xffffff)) ? effectiveTimestamp : 0;
	uint32_t timestampField = extendedTimestamp ? UINT32_C(0xffffff) : effectiveTimestamp;

	cs.m_streamID = streamID;
	cs.m_timestamp = timestamp;
	cs.m_timestampDelta = effectiveTimestamp;
	cs.m_length = len;
	cs.m_type = type_;
	cs.m_initted = true;
	cs.m_lastUsed = getCurrentTime();
	cs.m_timestampDeltaValid = CHUNK_TYPE_0 != chunkType;

	_pushChunkBasicHeader(m_rawOutputBuffer, chunkType, chunkStreamID);

	switch(chunkType)
	{
	case CHUNK_TYPE_0:
		_pushu24(m_rawOutputBuffer, timestampField);
		_pushu24(m_rawOutputBuffer, len);
		m_rawOutputBuffer.push_back(type_);
		_pushu32le(m_rawOutputBuffer, streamID);
		break;

	case CHUNK_TYPE_1:
		_pushu24(m_rawOutputBuffer, timestampField);
		_pushu24(m_rawOutputBuffer, len);
		m_rawOutputBuffer.push_back(type_);
		break;

	case CHUNK_TYPE_2:
		_pushu24(m_rawOutputBuffer, timestampField);
		break;

	case CHUNK_TYPE_3:
		break;
	}

	if(extendedTimestamp)
		_pushu32(m_rawOutputBuffer, extendedTimestamp);

	size_t writeAmount = std::min(len, m_sendChunkSize);
	m_rawOutputBuffer.insert(m_rawOutputBuffer.end(), payload, payload + writeAmount);

	cs.m_busy = writeAmount < len;

	return writeAmount;
}

size_t RTMP::queueNextChunk(int chunkStreamID, const uint8_t *payload, size_t cursor)
{
	assert(chunkStreamID >= 2);
	assert(chunkStreamID < NUM_CHUNKSTREAMS);

	auto &cs = m_sendChunkStreams[chunkStreamID];
	assert(cs.m_busy);

	_pushChunkBasicHeader(m_rawOutputBuffer, CHUNK_TYPE_3, chunkStreamID);

	uint32_t maybeExtendedTimestamp = cs.m_timestampDelta;
	if(maybeExtendedTimestamp >= UINT32_C(0xffffff))
		_pushu32(m_rawOutputBuffer, maybeExtendedTimestamp);

	size_t writeAmount = std::min(cs.m_length - cursor, m_sendChunkSize);
	m_rawOutputBuffer.insert(m_rawOutputBuffer.end(), payload + cursor, payload + cursor + writeAmount);

	cs.m_busy = cursor + writeAmount < cs.m_length;

	return writeAmount;
}

void RTMP::queueControlMessage(uint8_t type_, const uint8_t *payload, size_t len)
{
	queueStartChunk(CONTROL_CHUNKSTREAM_ID, 0, type_, 0, payload, len);
}

void RTMP::queueSetChunkSize()
{
	uint8_t buf[4];
	_setu32(buf, m_sendChunkSize & UINT32_C(0x7fffffff));
	queueControlMessage(TCMSG_SET_CHUNK_SIZE, buf, sizeof(buf));
}

void RTMP::queueAbortMessage(int chunkStreamID)
{
	uint8_t buf[4];
	_setu32(buf, chunkStreamID & UINT32_C(0xffffff));
	queueControlMessage(TCMSG_ABORT_MESSAGE, buf, sizeof(buf));
}

void RTMP::queueAck()
{
	uint8_t buf[4];
	_setu32(buf, m_receivedBytes);
	queueControlMessage(TCMSG_ACKNOWLEDGEMENT, buf, sizeof(buf));
}

void RTMP::sendAck()
{
	if(m_state >= RT_OPEN)
	{
		queueAck();
		m_lastAckSent = m_receivedBytes;
		scheduleWrite();
	}
}

void RTMP::sendAckIfNeeded()
{
	if(m_lastAckSent + m_windowAckSize <= m_receivedBytes)
		sendAck();
}

void RTMP::queueWindowAckSize(uint32_t newSize)
{
	uint8_t buf[4];
	_setu32(buf, newSize);
	queueControlMessage(TCMSG_WINDOW_ACK_SIZE, buf, sizeof(buf));
}

bool RTMP::trimSendQueues(bool abandonAll)
{
	Time now = getCurrentTime();

	for(int pri = PRI_HIGHEST; pri >= PRI_LOWEST; pri--)
	{
		auto &q = m_sendQueues[pri];

		while(not q.empty())
		{
			auto &first = q.firstValue();
			if(abandonAll)
				first->m_receipt->abandon();
			else
				first->m_receipt->abandonIfNeeded(now);
			if(not first->m_receipt->isAbandoned())
				break;
			if(first->m_offset and m_sendChunkStreams[first->m_chunkStream].m_busy)
			{
				queueAbortMessage(first->m_chunkStream);
				m_sendChunkStreams[first->m_chunkStream].m_busy = false;
			}
			first->m_receipt->useCountDown();
			q.removeFirst();
		}
	}

	return writeRawOutputBuffer();
}

void RTMP::scheduleWrite()
{
	if((not m_writeScheduled) and (m_state < RT_PROTOCOL_ERROR))
	{
		m_platform->notifyWhenWritable([this] { return onWritable(); });
		m_writeScheduled = true;
	}
}

bool RTMP::onWritable()
{
	if(writeRawOutputBuffer())
		return true;

	if(checkFlowControlWritable())
	{
		if(trimSendQueues(false))
			return true;

		for(int pri = PRI_HIGHEST; pri >= PRI_LOWEST; pri--)
		{
			auto &q = m_sendQueues[pri];
			if(not q.empty())
			{
				auto &first = q.firstValue();
				if(first->m_chunkStream < 0)
				{
					first->m_chunkStream = findChunkStream(first->m_streamID, first->m_messageType, first->m_payload.size());
					first->m_offset = queueStartChunk(first->m_chunkStream, first->m_streamID, first->m_messageType, first->m_timestamp, first->m_payload.data(), first->m_payload.size());
					first->m_receipt->start();
				}
				else
					first->m_offset += queueNextChunk(first->m_chunkStream, first->m_payload.data(), first->m_offset);

				if(not m_sendChunkStreams[first->m_chunkStream].m_busy)
				{
					first->m_receipt->useCountDown();
					q.removeFirst();
				}

				writeRawOutputBuffer();
				return true;
			}
		}

		// if we get here then we're completely flushed
		if(RT_CLOSING == m_state)
			setClosedState();
	}

	m_writeScheduled = false;
	return false;
}

int RTMP::findChunkStream(uint32_t streamID, uint8_t type_, size_t len) const
{
	// per §6.2 ¶2 TCMSG_USER_CONTROL messages SHOULD be sent on chunk stream 2.
	// however, they should also be queued normally and subject to queue precedence
	// so they go out in the right order.
	if((0 == streamID) and (TCMSG_USER_CONTROL == type_) and (len <= m_sendChunkSize) and not m_sendChunkStreams[CONTROL_CHUNKSTREAM_ID].m_busy)
		return CONTROL_CHUNKSTREAM_ID; // this chunk stream should never be marked busy

	int bestSoFar = -1;
	for(int i = CONTROL_CHUNKSTREAM_ID + 1; i < NUM_CHUNKSTREAMS; i++)
	{
		auto &cs = m_sendChunkStreams[i];
		if(not cs.m_initted)
			return i;
		if(cs.m_busy)
			continue;
		if(bestSoFar < 0)
			bestSoFar = i;
		if((streamID == cs.m_streamID) and (type_ == cs.m_type))
			return i;
		if(cs.m_streamID == streamID)
		{
			if(m_sendChunkStreams[bestSoFar].m_streamID != streamID)
				bestSoFar = i;
			if(cs.m_lastUsed < m_sendChunkStreams[bestSoFar].m_lastUsed)
				bestSoFar = i;
		}
		else if((m_sendChunkStreams[bestSoFar].m_streamID != streamID) and (cs.m_lastUsed < m_sendChunkStreams[bestSoFar].m_lastUsed))
			bestSoFar = i;
	}

	assert(bestSoFar > 0);
	return bestSoFar;
}

bool RTMP::checkFlowControlWritable() const
{
	uint32_t outstanding = (m_sentBytes & UINT32_C(0xffffffff)) - m_lastAckReceived;
	return (outstanding < m_peerBandwidth) and ((RT_OPEN == m_state) or (RT_CLOSING == m_state));
}

bool RTMP::onSetChunkSizeControlMessage(const uint8_t *payload, size_t len)
{
	if(len < 4)
		return false;

	uint32_t newChunkSize = _readu32(payload);
	if((0 == newChunkSize) or (newChunkSize > UINT32_C(0x7fffffff)))
		return false;

	m_recvChunkSize = newChunkSize;

	return true;
}

bool RTMP::onAbortMessageControlMessage(const uint8_t *payload, size_t len)
{
	if(len < 4)
		return false;

	uint32_t chunkStreamID = _readu32(payload);
	if((chunkStreamID < 2) or (chunkStreamID > 65535 + 64))
		return false;

	auto &cs = m_recvChunkStreams[chunkStreamID];
	if(not cs.m_initted)
		return false;

	cs.m_payload.clear();

	return true;
}

bool RTMP::onAckControlMessage(const uint8_t *payload, size_t len)
{
	if(len < 4)
		return false;

	m_lastAckReceived = _readu32(payload);
	scheduleWrite();

	return true;
}

bool RTMP::onWindowAckSizeControlMessage(const uint8_t *payload, size_t len)
{
	if(len < 4)
		return false;

	m_windowAckSize = _readu32(payload);
	sendAck();

	return true;
}

bool RTMP::onSetPeerBandwidthControlMessage(const uint8_t *payload, size_t len)
{
	if(len < 5)
		return false;

	uint32_t newPeerBandwidth = _readu32(payload);
	uint8_t limitType = payload[4];
	if(TC_SET_PEER_BW_LIMIT_DYNAMIC == limitType)
	{
		if(TC_SET_PEER_BW_LIMIT_HARD != m_lastPeerBandwidthType)
			return true;

		limitType = TC_SET_PEER_BW_LIMIT_HARD;
	}

	m_lastPeerBandwidthType = limitType;

	if(newPeerBandwidth != m_peerBandwidth)
		queueWindowAckSize(std::max(newPeerBandwidth / 2, UINT32_C(2)));

	if((TC_SET_PEER_BW_LIMIT_HARD == limitType) or (newPeerBandwidth < m_peerBandwidth))
		m_peerBandwidth = newPeerBandwidth;

	return true;
}

bool RTMP::onControlMessage(uint8_t messageType, const uint8_t *payload, size_t len)
{
	switch(messageType)
	{
	case TCMSG_SET_CHUNK_SIZE:
		return onSetChunkSizeControlMessage(payload, len);

	case TCMSG_ABORT_MESSAGE:
		return onAbortMessageControlMessage(payload, len);

	case TCMSG_ACKNOWLEDGEMENT:
		return onAckControlMessage(payload, len);

	case TCMSG_WINDOW_ACK_SIZE:
		return onWindowAckSizeControlMessage(payload, len);

	case TCMSG_SET_PEER_BW:
		return onSetPeerBandwidthControlMessage(payload, len);

	default:
		break;
	}

	return true;
}

void RTMP::onUserMessage(uint32_t streamID, uint8_t messageType, uint32_t timestamp, const uint8_t *payload, size_t len)
{
	if(onmessage and (m_state < RT_CLOSING))
		onmessage(streamID, messageType, timestamp, payload, len);
}

bool RTMP::onMessageCompleted(uint32_t streamID, uint8_t messageType, uint32_t timestamp, const uint8_t *payload, size_t len)
{
	switch(messageType)
	{
	case TCMSG_SET_CHUNK_SIZE:
	case TCMSG_ABORT_MESSAGE:
	case TCMSG_ACKNOWLEDGEMENT:
	case TCMSG_WINDOW_ACK_SIZE:
	case TCMSG_SET_PEER_BW:
		if(0 != streamID)
			return false;
		return onControlMessage(messageType, payload, len);

	case TCMSG_AGGREGATE:
		break; // TODO handle these if configured

	default:
		break;
	}

	onUserMessage(streamID, messageType, timestamp, payload, len);
	return true;
}

void RTMP::queueHandshake01()
{
	m_rawOutputBuffer.push_back(RTMP_VERSION);

	uint32_t timestamp = timeAsTimestamp(getInstanceAge());
	_pushu32(m_rawOutputBuffer, timestamp);
	_pushu32(m_rawOutputBuffer, 0);
	m_rawOutputBuffer.insert(m_rawOutputBuffer.end(), 1536 - 8, m_isServer ? 'S' : 'C');

	scheduleWrite();
}

void RTMP::queueHandshake2(const uint8_t *handshake1)
{
	m_rawOutputBuffer.insert(m_rawOutputBuffer.end(), handshake1, handshake1 + 4);
	_pushu32(m_rawOutputBuffer, timeAsTimestamp(getInstanceAge()));
	m_rawOutputBuffer.insert(m_rawOutputBuffer.end(), handshake1 + 8, handshake1 + 1536);

	scheduleWrite();
}

void RTMP::shiftInputBuffer(size_t amount)
{
	if(amount)
	{
		assert(amount <= m_inputBuffer.size());

		size_t newSize = m_inputBuffer.size() - amount;
		uint8_t *buf = m_inputBuffer.data();
		::memmove(buf, buf + amount, newSize);
		m_inputBuffer.resize(newSize);
	}
}

long RTMP::onOpenInput(const uint8_t *bytes, const uint8_t *limit, size_t remaining)
{
	const uint8_t *cursor = bytes;
	uint8_t chunkType = *cursor & CHUNK_TYPE_MASK;
	uint8_t maybeChunkStreamID = *cursor & CHUNK_STREAM_ID_MASK;
	size_t needed = 1;

	cursor++;

	if(maybeChunkStreamID < 2)
		needed++;
	if(1 == maybeChunkStreamID)
		needed++;

	switch(chunkType)
	{
	case CHUNK_TYPE_0: needed += 11; break;
	case CHUNK_TYPE_1: needed += 7; break;
	case CHUNK_TYPE_2: needed += 3; break;
	default: break;
	}

	if(remaining < needed)
		return 0;

	uint32_t chunkStreamID;
	if(0 == maybeChunkStreamID)
		chunkStreamID = *cursor++ + 64;
	else if(1 == maybeChunkStreamID)
	{
		// spec mismatch, Adobe sends little-endian, spec implies big-endian :(
		chunkStreamID = cursor[0] + (cursor[1] << 8) + 64;
		cursor += 2;
	}
	else
		chunkStreamID = maybeChunkStreamID;

	auto &cs = m_recvChunkStreams[chunkStreamID];
	if((not cs.m_initted) and (CHUNK_TYPE_0 != chunkType))
		return -1;

	uint32_t timestamp;
	if(chunkType < CHUNK_TYPE_3)
	{
		timestamp = _readu24(cursor);
		cursor += 3;
	}
	else
		timestamp = cs.m_timestampDelta;

	uint32_t messageLength;
	uint8_t messageTypeID;
	if(chunkType < CHUNK_TYPE_2)
	{
		messageLength = _readu24(cursor);
		cursor += 3;
		messageTypeID = *cursor++;
	}
	else
	{
		messageLength = cs.m_length;
		messageTypeID = cs.m_type;
	}

	size_t messageLengthRemaining = messageLength;
	if(CHUNK_TYPE_3 == chunkType)
		messageLengthRemaining -= cs.m_payload.size();

	size_t chunkPayloadLength = std::min(m_recvChunkSize, messageLengthRemaining);
	needed += chunkPayloadLength;
	if(remaining < needed)
		return 0;

	uint32_t streamID;
	if(chunkType < CHUNK_TYPE_1)
	{
		// ugh, little endian for some reason
		streamID  = *cursor++;
		streamID += (*cursor++ << 8);
		streamID += (*cursor++ << 16);
		streamID += (*cursor++ << 24);
	}
	else
		streamID = cs.m_streamID;

	if(timestamp >= UINT32_C(0xffffff))
	{
		needed += 4;
		if(remaining < needed)
			return 0;

		timestamp = _readu32(cursor); cursor += 4;
	}

	switch(chunkType)
	{
	case CHUNK_TYPE_0:
		cs.m_streamID = streamID;
		cs.m_timestamp = timestamp;
		cs.m_timestampDelta = timestamp;
		cs.m_length = messageLength;
		cs.m_type = messageTypeID;
		cs.m_payload.clear();
		cs.m_initted = true;
		break;

	case CHUNK_TYPE_1:
		cs.m_timestampDelta = timestamp;
		cs.m_timestamp += timestamp;
		cs.m_length = messageLength;
		cs.m_type = messageTypeID;
		cs.m_payload.clear();
		break;

	case CHUNK_TYPE_2:
		cs.m_timestampDelta = timestamp;
		cs.m_timestamp += timestamp;
		cs.m_payload.clear();
		break;

	case CHUNK_TYPE_3:
		cs.m_timestampDelta = timestamp;
		if(0 == cs.m_payload.size())
			cs.m_timestamp += timestamp;
		break;
	}

	assert(cursor + chunkPayloadLength <= limit);

	cs.m_payload.insert(cs.m_payload.end(), cursor, cursor + chunkPayloadLength);
	cursor += chunkPayloadLength;

	assert((size_t)(cursor - bytes) == (size_t)needed);
	assert(cs.m_payload.size() <= cs.m_length);

	if(cs.m_payload.size() == cs.m_length)
	{
		onMessageCompleted(cs.m_streamID, cs.m_type, cs.m_timestamp, cs.m_payload.data(), cs.m_payload.size());
		cs.m_payload.clear();
	}

	return needed;
}

long RTMP::onUninitializedInput(const uint8_t *bytes)
{
	if(*bytes < RTMP_VERSION)
		return -1;
	if(*bytes >= 32) // not RTMP
		return -1;

	if(m_isServer)
		queueHandshake01();

	m_state = RT_VERSION_SENT;

	return 1;
}

long RTMP::onVersionSentInput(const uint8_t *bytes, size_t remaining)
{
	if(remaining < 1536)
		return 0;

	queueHandshake2(bytes);
	m_state = RT_ACK_SENT;

	return 1536;
}

long RTMP::onAckSentInput(const uint8_t *, size_t remaining)
{
	if(remaining < 1536)
		return 0;

	// TODO: use time timestamps in the echo message to... do something i guess, like make an
	// initial RTT measurement (though really the flight time of the echo should be used instead).

	m_state = RT_OPEN;

	if(m_sendChunkSize != DEFAULT_CHUNK_SIZE)
		queueSetChunkSize();

	scheduleWrite(); // in case there are queued messages

	if(onopen)
		onopen();

	return 1536;
}

long RTMP::onInput(const uint8_t *bytes, const uint8_t *limit)
{
	size_t remaining = limit - bytes;
	assert(remaining > 0);

	switch(m_state)
	{
	case RT_OPEN:
	case RT_CLOSING:
		return onOpenInput(bytes, limit, remaining);

	case RT_UNINITIALIZED:
		return onUninitializedInput(bytes);

	case RT_VERSION_SENT:
		return onVersionSentInput(bytes, remaining);

	case RT_ACK_SENT:
		return onAckSentInput(bytes, remaining);

	default:
		break;
	}

	return -1;
}

void RTMP::clearCallbacks()
{
	onmessage = nullptr;
	onopen = nullptr;
	onerror = nullptr;
}

void RTMP::setClosedState()
{
	Task onerror_f;

	if(m_state != RT_PROTOCOL_ERROR)
	{
		m_state = RT_PROTOCOL_ERROR;
		trimSendQueues(true);
		m_platform->onClosed();
		swap(onerror_f, onerror);
	}
	clearCallbacks();

	if(onerror_f)
		onerror_f();
}

} } } // namespace com::zenomt::rtmp
