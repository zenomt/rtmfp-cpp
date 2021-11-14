#pragma once

// Copyright © 2021 Michael Thornburgh
// SPDX-License-Identifier: MIT

#include <cmath>
#include <cstdint>
#include <map>

#include "rtmfp/List.hpp"
#include "rtmfp/Priority.hpp"
#include "rtmfp/WriteReceipt.hpp"

namespace com { namespace zenomt { namespace rtmp {

class IPlatformAdapter;

const size_t DEFAULT_CHUNK_SIZE = 128;
const int CONTROL_CHUNKSTREAM_ID = 2;
const uint8_t CHUNK_TYPE_MASK = 0xc0;
const uint8_t CHUNK_STREAM_ID_MASK = 0x3f;
enum {
	CHUNK_TYPE_0 = 0 << 6,
	CHUNK_TYPE_1 = 1 << 6,
	CHUNK_TYPE_2 = 2 << 6,
	CHUNK_TYPE_3 = 3 << 6,
};

const uint8_t RTMP_VERSION = 3; // the only version of RTMP we support

class RTMP : public Object {
public:
	using Bytes = std::vector<uint8_t>;
	enum State { RT_UNKNOWN, RT_UNINITIALIZED, RT_VERSION_SENT, RT_ACK_SENT, RT_OPEN, RT_CLOSING, RT_PROTOCOL_ERROR };

	RTMP(IPlatformAdapter *platform);
	bool init(bool isServer); // answer false if already initted or on error, true otherwise

	void   setChunkSize(size_t newSize);
	size_t getChunkSize() const;

	std::shared_ptr<WriteReceipt> write(Priority pri, uint32_t streamID, uint8_t messageType, uint32_t timestamp, const void *payload, size_t len, Time startWithin = INFINITY, Time finishWithin = INFINITY);
	std::shared_ptr<WriteReceipt> write(Priority pri, uint32_t streamID, uint8_t messageType, uint32_t timestamp, const Bytes &payload, Time startWithin = INFINITY, Time finishWithin = INFINITY);

	Time getUnsentAge(Priority pri) const;
	Time getUnstartedAge(Priority pri) const;
	Time getInstanceAge() const;
	Time getCurrentTime() const;
	uint32_t timeAsTimestamp(Time t) const;

	std::function<void(uint32_t streamID, uint8_t messageType, uint32_t timestamp, const uint8_t *payload, size_t len)> onmessage;

	Task onopen; // Called when the protocol transitions to RT_OPEN
	Task onerror; // Called if the protocol closes unexpectedly

	void close();

	void setSimpleMode(bool isSimple); // only use Type 0 chunks to start messages

	// -- Used by the Platform Adapter

	// Input new bytes to the protocol. Answer true on success, false on error (like protocol error).
	bool onReceiveBytes(const void *bytes, size_t len);

	void onInterfaceDidClose();

protected:
	struct Message;
	static const int NUM_CHUNKSTREAMS = 24; // must be at least NUM_PRIORITIES + 3

	struct ChunkStreamState {
		uint32_t m_streamID { 0 };
		uint32_t m_timestamp { 0 };
		uint32_t m_timestampDelta { 0 };
		size_t   m_length { 0 };
		uint8_t  m_type { 0 };
		bool     m_initted { false };
		bool     m_timestampDeltaValid { false };
	};

	struct RecvChunkStreamState : public ChunkStreamState {
		Bytes m_payload;
	};

	struct SendChunkStreamState : public ChunkStreamState {
		Time   m_lastUsed { -INFINITY };
		bool   m_busy { false };
	};

	bool writeRawOutputBuffer();
	size_t queueStartChunk(int chunkStreamID, uint32_t streamID, uint8_t type_, uint32_t timestamp, const uint8_t *payload, size_t len);
	size_t queueNextChunk(int chunkStreamID, const uint8_t *payload, size_t cursor);
	void queueControlMessage(uint8_t type_, const uint8_t *payload, size_t len);
	void queueSetChunkSize();
	void queueAbortMessage(int chunkStreamID);
	void queueAck();
	void sendAck();
	void sendAckIfNeeded();
	void queueWindowAckSize(uint32_t newSize);
	bool trimSendQueues(bool abandonAll);
	void scheduleWrite();
	bool onWritable();
	int findChunkStream(uint32_t streamID, uint8_t type_, size_t len) const;
	bool checkFlowControlWritable() const;
	void onUserMessage(uint32_t streamID, uint8_t messageType, uint32_t timestamp, const uint8_t *payload, size_t len);
	bool onSetChunkSizeControlMessage(const uint8_t *payload, size_t len);
	bool onAbortMessageControlMessage(const uint8_t *payload, size_t len);
	bool onAckControlMessage(const uint8_t *payload, size_t len);
	bool onWindowAckSizeControlMessage(const uint8_t *payload, size_t len);
	bool onSetPeerBandwidthControlMessage(const uint8_t *payload, size_t len);
	bool onControlMessage(uint8_t messageType, const uint8_t *payload, size_t len);
	bool onMessageCompleted(uint32_t streamID, uint8_t messageType, uint32_t timestamp, const uint8_t *payload, size_t len);
	void queueHandshake01();
	void queueHandshake2(const uint8_t *handshake1); // handshake1 points to 1536 bytes
	void shiftInputBuffer(size_t amount);
	long onOpenInput(const uint8_t *bytes, const uint8_t *limit, size_t remaining);
	long onUninitializedInput(const uint8_t *bytes);
	long onVersionSentInput(const uint8_t *bytes, size_t remaining);
	long onAckSentInput(const uint8_t *bytes, size_t remaining);
	long onInput(const uint8_t *bytes, const uint8_t *limit);
	void clearCallbacks();
	void setClosedState();

	std::map<uint32_t, RecvChunkStreamState> m_recvChunkStreams; // chunkstreamID -> state
	SendChunkStreamState m_sendChunkStreams[NUM_CHUNKSTREAMS];
	List<std::shared_ptr<Message>> m_sendQueues[NUM_PRIORITIES];
	Bytes m_inputBuffer;
	Bytes m_rawOutputBuffer;

	IPlatformAdapter *m_platform;
	State    m_state;
	bool     m_isServer;
	bool     m_simpleMode;
	Time     m_epoch;
	bool     m_writeScheduled;
	size_t   m_sendChunkSize;
	size_t   m_recvChunkSize;
	size_t   m_sentBytes;
	size_t   m_receivedBytes;
	size_t   m_windowAckSize;
	size_t   m_lastAckSent;
	uint32_t m_lastAckReceived;
	size_t   m_peerBandwidth;
	uint8_t  m_lastPeerBandwidthType;
};

class IPlatformAdapter {
public:
	virtual ~IPlatformAdapter() {}

	virtual Time getCurrentTime() = 0;

	using onwritable_f = std::function<bool(void)>;
	virtual void notifyWhenWritable(const onwritable_f &onwritable) = 0;

	// only called (and at most once) from onwritable(). answer true on success,
	// false on failure (like no longer open). implementation MUST support receiving
	// (and if necessary buffering) any length of write.
	virtual bool writeBytes(const void *bytes, size_t len) = 0;

	// Called when the protocol has concluded and has no more data to send, including
	// on error or flush of all messages.
	virtual void onClosed() = 0;
};

} } } // namespace com::zenomt::rtmp
