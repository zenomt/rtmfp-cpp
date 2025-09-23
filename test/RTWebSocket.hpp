#pragma once

// Copyright © 2022 Michael Thornburgh
// SPDX-License-Identifier: MIT

#include <cmath>
#include <deque>
#include <map>
#include <string>

#include "rtmfp/List.hpp"
#include "rtmfp/Priority.hpp"
#include "rtmfp/WriteReceipt.hpp"

#include "IStreamPlatformAdapter.hpp"

namespace com { namespace zenomt { namespace rtws {

using Bytes = std::vector<uint8_t>;

enum {
	MSG_PING             = 0x01,
	MSG_PING_REPLY       = 0x41,
	MSG_ACK_WINDOW       = 0x0a,
	MSG_FLOW_OPEN        = 0x10,
	MSG_FLOW_OPEN_RETURN = 0x30,
	MSG_DATA_LAST        = 0x1d,
	MSG_DATA_MORE        = 0x3d,
	MSG_DATA_ABANDON     = 0x1a,
	MSG_FLOW_CLOSE       = 0x1c,
	MSG_DATA_ACK         = 0x5a,
	MSG_FLOW_CLOSE_ACK   = 0x5c,
	MSG_FLOW_EXCEPTION   = 0x5e
};

constexpr size_t MIN_ACK_WINDOW = 1400 * 2;
constexpr size_t MAX_ACK_WINDOW = 1400 * 8;
constexpr size_t MAX_CHUNK_SIZE = 1 << 20; // 1MB, way too big

class SendFlow;
class RecvFlow;
class IMessagePlatformAdapter;

class RTWebSocket : public Object {
friend class SendFlow;
friend class RecvFlow;
public:
	RTWebSocket(std::shared_ptr<IMessagePlatformAdapter> adapter);
	RTWebSocket() = delete;
	~RTWebSocket();

	bool init(); // To be called when adapter is ready for callbacks to be connected and called.

	std::shared_ptr<SendFlow> openFlow(const void *metadataBytes, size_t metadataLen, Priority pri = PRI_ROUTINE);
	std::shared_ptr<SendFlow> openFlow(const Bytes &metadata, Priority pri = PRI_ROUTINE);

	std::function<void(std::shared_ptr<RecvFlow> flow)> onRecvFlow;

	void close();
	bool isOpen() const;

	Task onError;

	Duration getRTT() const;
	Duration getBaseRTT() const;

	size_t getBytesInFlight() const;
	size_t outstandingThresh { 1024 * 64 };
	size_t minOutstandingThresh { 1024 * 64 };
	Duration maxAdditionalDelay { 0.050 };

	size_t chunkSize { 1400 };

	Time getCurrentTime();

protected:
	std::shared_ptr<SendFlow> basicOpenFlow(const void *metadataBytes, size_t metadataLen, Priority pri, uintmax_t *returnFlowID_ptr);
	void sendBytes(const void *bytes, size_t len);
	void sendBytes(const Bytes &bytes);
	bool onBinaryMessage(const void *bytes, size_t len);

	// answer false for a protocol error, true to carry on
	bool onPingMessage(const uint8_t *bytes, const uint8_t *limit);
	bool onPingReplyMessage(const uint8_t *bytes, const uint8_t *limit);
	bool onAckWindowMessage(const uint8_t *bytes, const uint8_t *limit);
	bool onFlowOpenMessage(uint8_t msgType, const uint8_t *bytes, const uint8_t *limit);
	bool onDataMessage(uint8_t msgType, size_t messageLen, const uint8_t *bytes, const uint8_t *limit);
	bool onDataAbandonMessage(const uint8_t *bytes, const uint8_t *limit);
	bool onFlowCloseMessage(const uint8_t *bytes, const uint8_t *limit);
	bool onDataAckMessage(const uint8_t *bytes, const uint8_t *limit);
	bool onFlowCloseAckMessage(const uint8_t *bytes, const uint8_t *limit);
	bool onFlowExceptionMessage(const uint8_t *bytes, const uint8_t *limit);

	void ackIfNeeded();
	void queueAck(std::shared_ptr<RecvFlow> recvFlow, bool immediate);
	void scheduleAckNow();
	void sendAcks();
	void queueTransmission(std::shared_ptr<SendFlow> sendFlow);
	void scheduleTransmission();
	bool transmit();
	void startRTT();
	void measureRTT();
	void addRTT(Duration rtt);

	void safeDoLater(Object *retainThis, const Task &task);
	void closeWithError();

	std::shared_ptr<IMessagePlatformAdapter> m_adapter;
	bool m_open { false };
	bool m_userOpen { true };
	bool m_ackNow { false };
	bool m_sendNow { false };
	size_t m_recvAccumulator { 0 };
	size_t m_ackWindow { MIN_ACK_WINDOW };
	size_t m_flowBytesSent { 0 };
	size_t m_flowBytesAcked { 0 };
	size_t m_rttPosition { 0 };
	size_t m_rttPreviousPosition { 0 };
	Time m_rttAnchor { -1.0 };
	Duration m_baseRTTCache { 0.1 };
	Duration m_smoothedRTT { 0.1 };
	List<std::shared_ptr<SendFlow>> m_sendFlows;
	std::map<uintmax_t, std::shared_ptr<RecvFlow>> m_recvFlows;
	std::set<std::shared_ptr<RecvFlow>> m_ackFlows;
	List<std::shared_ptr<SendFlow>> m_transmissionWork[NUM_PRIORITIES];

	// base rtt measurements
	struct RTTMeasurement {
		Duration min_rtt;
		Time     origin;
	};
	std::deque<RTTMeasurement> m_rttMeasurements;
};

class SendFlow : public Object {
friend class RTWebSocket;
public:
	~SendFlow();

	// using RTMFP-style names instead of (Javascript) RTWebSocket ones.
	std::shared_ptr<WriteReceipt> write(const void *message, size_t len, Duration startWithin = INFINITY, Duration finishWithin = INFINITY);
	std::shared_ptr<WriteReceipt> write(const Bytes &message, Duration startWithin = INFINITY, Duration finishWithin = INFINITY);

	bool isOpen() const;
	void close();

	Priority getPriority() const;
	void setPriority(Priority pri);

	using onwritable_f = std::function<bool(void)>;
	bool isWritable() const; // Note: advisory, like RTMFP. Writes are always buffered.
	void notifyWhenWritable(const onwritable_f &onwritable);
	void setBufferCapacity(size_t bufferLengthInBytes);
	size_t getBufferCapacity() const;
	size_t getBufferedSize() const;
	size_t getRecvBufferBytesAvailable() const; // The last received window advertisement.
	Duration getUnsentAge() const; // The age of the oldest unsent message in the transmit queue.

	// Called if this flow is rejected by the receiver.
	using onException_f = std::function<void(uintmax_t reason, const std::string &description)>;
	onException_f onException;

	// Called when a new associated return flow starts. flow must be accepted during
	// this callback or it will be rejected automatically.
	std::function<void(std::shared_ptr<RecvFlow> flow)> onRecvFlow;

protected:
	SendFlow(std::shared_ptr<RTWebSocket> owner, uintmax_t flowID, uintmax_t *returnFlowID_ptr, const void *metadataBytes, size_t metadataLen);
	SendFlow() = delete;

	void queueWritableNotify();
	void doWritable();
	bool transmit(int pri);
	void queueTransmission();
	void queueTrimSendBufferIfNeeded();
	void trimSendBuffer();
	bool transmitOneFragment();

	void onAck(uintmax_t deltaBytes, uintmax_t bufferAdvertisement);
	void onExceptionMessage(uintmax_t reason, const uint8_t *description, const uint8_t *descriptionLimit);

	std::shared_ptr<RTWebSocket> m_owner;
	uintmax_t m_flowID;
	Priority m_priority { PRI_ROUTINE };
	size_t m_bufferCapacity { 65536 };
	size_t m_recvBufferBytesAvailable { 65536 };
	size_t m_sentByteCount { 0 };
	size_t m_sendThroughAllowed { 65536 };
	size_t m_ackedPosition { 0 };
	bool m_open { true };
	bool m_sentClose { false };
	std::shared_ptr<Bytes> m_flowOpenMessage;
	onwritable_f m_onwritable;
	bool m_writablePending { false };
	size_t m_abandonCount { 0 };
	bool m_exception { false };
	bool m_trimPending { false };
	Time m_lastTrimQueued { -INFINITY };

	struct WriteMessage;
	SumList<std::shared_ptr<WriteMessage>> m_sendBuffer;
};

class RecvFlow : public Object {
friend class RTWebSocket;
public:
	~RecvFlow();

	bool isOpen() const;
	void accept(); // Call this during the onRecvFlow callback to accept a new receiving flow.
	void close();
	void close(uintmax_t reason);
	void close(uintmax_t reason, const std::string &description);
	size_t getBufferAdvertisement() const;
	void setBufferCapacity(size_t bufferLengthInBytes);
	size_t getBufferCapacity() const;
	size_t getBufferedSize() const;

	void setPaused(bool paused);
	bool getPaused() const;

	Bytes getMetadata() const;

	// Open a new flow in return/response to this flow.
	std::shared_ptr<SendFlow> openReturnFlow(const void *metadataBytes, size_t metadataLen, Priority pri = PRI_ROUTINE);
	std::shared_ptr<SendFlow> openReturnFlow(const Bytes &metadata, Priority pri = PRI_ROUTINE);

	// This function is called as complete messages are received.
	// Messages are discarded if this callback is not set.
	std::function<void(const uint8_t *bytes, size_t len, uintmax_t messageNumber)> onMessage;

	Task onComplete;

protected:
	RecvFlow(std::shared_ptr<RTWebSocket> owner, uintmax_t flowID, const uint8_t *metadataBytes, const uint8_t *metadataLimit);
	RecvFlow() = delete;

	void queueAck(bool immediate);
	void sendAck();
	void onFlowCloseMessage();
	void onData(bool more, const uint8_t *bytes, const uint8_t *limit, size_t chunkLength);
	void onDataAbandon(uintmax_t countMinusOne);

	void queueDelivery();
	void deliverData();
	void deliverCompleteAndClose();

	std::shared_ptr<RTWebSocket> m_owner;
	uintmax_t m_flowID;
	Bytes m_metadata;
	bool m_userOpen { false };
	bool m_open { true };
	bool m_paused { false };
	size_t m_bufferCapacity { 2097151 }; // max 3-byte VLU
	size_t m_receiveBufferByteLength { 0 };
	size_t m_receivedByteCount { 0 };
	size_t m_ackThresh { 0 };
	bool m_complete { false };
	bool m_sentComplete { false };
	bool m_sentCloseAck { false };
	uintmax_t m_nextMessageNumber { 1 };
	bool m_deliveryPending { false };

	struct ReadMessage;
	List<std::shared_ptr<ReadMessage>> m_receiveBuffer;
};

class IMessagePlatformAdapter : public IStreamPlatformAdapter {
public:
	// This interface changes the semantics of IStreamPlatformAdapter:
	// onreceivebytes_f and writeBytes receive and send whole (binary)
	// messages, respectively. The adapter takes care of any necessary
	// message framing (for example, in WebSocket binary messages).
};

} } } // namespace com::zenomt::rtws
