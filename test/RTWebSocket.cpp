// Copyright © 2022 Michael Thornburgh
// SPDX-License-Identifier: MIT

#include "rtmfp/VLU.hpp"

#include "RTWebSocket.hpp"

namespace com { namespace zenomt { namespace rtws {

constexpr Time RTT_HISTORY_THRESH = 30.0;
constexpr size_t RTT_HISTORY_CAPACITY = 6;

// --- RTWebSocket

RTWebSocket::RTWebSocket(std::shared_ptr<IMessagePlatformAdapter> adapter) : m_adapter(adapter)
{
	m_adapter->setOnReceiveBytesCallback([this] (const void *bytes, size_t len) { return onBinaryMessage(bytes, len); });
	m_adapter->setOnStreamDidCloseCallback([this] { closeWithError(); });
}

RTWebSocket::~RTWebSocket()
{
}

bool RTWebSocket::init()
{
	if(m_open or not m_userOpen)
		return false;

	m_open = true;

	return true;
}

std::shared_ptr<SendFlow> RTWebSocket::openFlow(const void *metadataBytes, size_t metadataLen, Priority pri)
{
	return basicOpenFlow(metadataBytes, metadataLen, pri, nullptr);
}

std::shared_ptr<SendFlow> RTWebSocket::openFlow(const Bytes &metadata, Priority pri)
{
	return openFlow(metadata.data(), metadata.size(), pri);
}

void RTWebSocket::close()
{
	if(not m_userOpen)
		return;
	m_open = m_userOpen = false;

	onRecvFlow = nullptr;
	onError = nullptr;

	m_adapter->onClientClosed();

	while(not m_sendFlows.empty())
	{
		auto each = m_sendFlows.firstValue();
		m_sendFlows.removeFirst();

		if(each and each->isOpen())
		{
			each->onExceptionMessage(0, nullptr, nullptr);
			each->trimSendBuffer();
		}
	}

	while(not m_recvFlows.empty())
	{
		auto it = m_recvFlows.begin();
		auto each = it->second;
		m_recvFlows.erase(it);

		if(each and each->isOpen())
		{
			each->onFlowCloseMessage();
			each->deliverCompleteAndClose();
		}
	}

	m_ackFlows.clear();

	for(int x = 0; x < NUM_PRIORITIES; x++)
		m_transmissionWork[x].clear();
}

bool RTWebSocket::isOpen() const
{
	return m_open;
}

Time RTWebSocket::getRTT() const
{
	return m_smoothedRTT;
}

Time RTWebSocket::getBaseRTT() const
{
	return m_baseRTTCache;
}

size_t RTWebSocket::getBytesInFlight() const
{
	return m_flowBytesSent - m_flowBytesAcked;
}

Time RTWebSocket::getCurrentTime()
{
	if(not m_open)
		return INFINITY;

	return m_adapter->getCurrentTime();
}

// --- RTWebSocket protected

std::shared_ptr<SendFlow> RTWebSocket::basicOpenFlow(const void *metadataBytes, size_t metadataLen, Priority pri, uintmax_t *returnFlowID_ptr)
{
	if(not isOpen())
		return nullptr;

	long flowID = m_sendFlows.append(nullptr);
	auto flow = share_ref(new SendFlow(share_ref(this), (uintmax_t)flowID, returnFlowID_ptr, metadataBytes, metadataLen), false);
	m_sendFlows.at(flowID) = flow;

	flow->setPriority(pri);
	queueTransmission(flow);

	return flow;
}

void RTWebSocket::sendBytes(const void *bytes, size_t len)
{
	if(m_open)
		m_adapter->writeBytes(bytes, len);
}

void RTWebSocket::sendBytes(const Bytes &bytes)
{
	return sendBytes(bytes.data(), bytes.size());
}

bool RTWebSocket::onBinaryMessage(const void *bytes, size_t len)
{
	if(0 == len)
		return true;

	const uint8_t *cursor = (const uint8_t *)bytes;
	const uint8_t *limit = cursor + len;
	bool rv = true;

	uint8_t msgType = *cursor++;
	switch(msgType)
	{
	case MSG_PING:
		rv = onPingMessage(cursor, limit);
		break;

	case MSG_PING_REPLY:
		rv = onPingReplyMessage(cursor, limit);
		break;

	case MSG_ACK_WINDOW:
		rv = onAckWindowMessage(cursor, limit);
		break;

	case MSG_FLOW_OPEN:
	case MSG_FLOW_OPEN_RETURN:
		rv = onFlowOpenMessage(msgType, cursor, limit);
		break;

	case MSG_DATA_LAST:
	case MSG_DATA_MORE:
		rv = onDataMessage(msgType, len, cursor, limit);
		break;

	case MSG_DATA_ABANDON:
		rv = onDataAbandonMessage(cursor, limit);
		break;

	case MSG_FLOW_CLOSE:
		rv = onFlowCloseMessage(cursor, limit);
		break;

	case MSG_DATA_ACK:
		rv = onDataAckMessage(cursor, limit);
		break;

	case MSG_FLOW_CLOSE_ACK:
		rv = onFlowCloseAckMessage(cursor, limit);
		break;

	case MSG_FLOW_EXCEPTION:
		rv = onFlowExceptionMessage(cursor, limit);
		break;

	default:
		break;
	}

	if(not rv)
		closeWithError();

	return rv;
}

bool RTWebSocket::onPingMessage(const uint8_t *bytes, const uint8_t *limit)
{
	Bytes msg;
	msg.push_back(MSG_PING_REPLY);
	msg.insert(msg.end(), bytes, limit);
	sendBytes(msg);
	return true;
}

bool RTWebSocket::onPingReplyMessage(const uint8_t *bytes, const uint8_t *limit)
{
	return true;
}

bool RTWebSocket::onAckWindowMessage(const uint8_t *bytes, const uint8_t *limit)
{
	uintmax_t ackWindow = 0;
	if(0 == rtmfp::VLU::parse(bytes, limit, &ackWindow))
		return false;

	m_ackWindow = std::max((size_t)ackWindow, MIN_ACK_WINDOW);
	m_recvAccumulator = 0;

	return true;
}

bool RTWebSocket::onFlowOpenMessage(uint8_t msgType, const uint8_t *bytes, const uint8_t *limit)
{
	const uint8_t *cursor = bytes;
	size_t rv;

	uintmax_t flowID = 0;
	cursor += (rv = rtmfp::VLU::parse(cursor, limit, &flowID));
	if(0 == rv)
		return false;

	if(m_recvFlows.count(flowID)) // already in use
		return false;

	bool hasReturnAssociation = MSG_FLOW_OPEN_RETURN == msgType;
	uintmax_t returnAssociationID = 0;
	if(hasReturnAssociation)
	{
		cursor += (rv = rtmfp::VLU::parse(cursor, limit, &returnAssociationID));
		if(0 == rv)
			return false;
	}

	// cursor points to metadata, extends to limit

	std::shared_ptr<SendFlow> returnFlowAssociation;
	if(m_sendFlows.has(returnAssociationID))
		returnFlowAssociation = m_sendFlows.at(returnAssociationID);
	
	auto recvFlow = share_ref(new RecvFlow(share_ref(this), flowID, cursor, limit), false);
	m_recvFlows[flowID] = recvFlow;

	if(hasReturnAssociation and ((not returnFlowAssociation) or not returnFlowAssociation->isOpen()))
	{
		recvFlow->close(0, "return association not found");
		return true; // user error, not protocol error
	}

	if(hasReturnAssociation)
	{
		if(returnFlowAssociation->onRecvFlow)
			returnFlowAssociation->onRecvFlow(recvFlow);
	}
	else
	{
		if(onRecvFlow)
			onRecvFlow(recvFlow);
	}

	if(not recvFlow->isOpen())
		recvFlow->close(0, "not accepted");

	queueAck(recvFlow, true);

	return true;
}

bool RTWebSocket::onDataMessage(uint8_t msgType, size_t messageLen, const uint8_t *bytes, const uint8_t *limit)
{
	const uint8_t *cursor = bytes;
	size_t rv;

	uintmax_t flowID = 0;
	cursor += (rv = rtmfp::VLU::parse(cursor, limit, &flowID));
	if(0 == rv)
		return false;

	auto it = m_recvFlows.find(flowID);
	if(it == m_recvFlows.end())
		return false;

	m_recvAccumulator += messageLen;
	if(m_recvAccumulator >= m_ackWindow)
	{
		scheduleAckNow();
		m_recvAccumulator = m_recvAccumulator % m_ackWindow;
	}

	it->second->onData(MSG_DATA_MORE == msgType, cursor, limit, messageLen);

	return true;
}

bool RTWebSocket::onDataAbandonMessage(const uint8_t *bytes, const uint8_t *limit)
{
	const uint8_t *cursor = bytes;
	size_t rv;

	uintmax_t flowID = 0;
	cursor += (rv = rtmfp::VLU::parse(cursor, limit, &flowID));
	if(0 == rv)
		return false;

	uintmax_t countMinusOne = 0;
	if(cursor < limit)
	{
		cursor += (rv = rtmfp::VLU::parse(cursor, limit, &countMinusOne));
		if(0 == rv)
			return false;
	}

	auto it = m_recvFlows.find(flowID);
	if(it == m_recvFlows.end())
		return false;

	it->second->onDataAbandon(countMinusOne);

	return true;
}

bool RTWebSocket::onFlowCloseMessage(const uint8_t *bytes, const uint8_t *limit)
{
	uintmax_t flowID = 0;
	if(0 == rtmfp::VLU::parse(bytes, limit, &flowID))
		return false;

	auto it = m_recvFlows.find(flowID);
	if(it == m_recvFlows.end())
		return false;

	it->second->onFlowCloseMessage();
	m_recvFlows.erase(flowID);

	return true;
}

bool RTWebSocket::onDataAckMessage(const uint8_t *bytes, const uint8_t *limit)
{
	const uint8_t *cursor = bytes;
	size_t rv;

	uintmax_t flowID = 0;
	cursor += (rv = rtmfp::VLU::parse(cursor, limit, &flowID));
	if(0 == rv)
		return false;

	uintmax_t deltaBytes = 0;
	cursor += (rv = rtmfp::VLU::parse(cursor, limit, &deltaBytes));
	if(0 == rv)
		return false;

	uintmax_t bufferAdvertisement = 0;
	cursor += (rv = rtmfp::VLU::parse(cursor, limit, &bufferAdvertisement));
	if(0 == rv)
		return false;

	if(not m_sendFlows.has(flowID))
		return false;

	m_flowBytesAcked += deltaBytes;
	m_sendFlows.at(flowID)->onAck(deltaBytes, bufferAdvertisement);
	measureRTT();

	return true;
}

bool RTWebSocket::onFlowCloseAckMessage(const uint8_t *bytes, const uint8_t *limit)
{
	uintmax_t flowID = 0;
	if(0 == rtmfp::VLU::parse(bytes, limit, &flowID))
		return false;

	if((not m_sendFlows.has(flowID)) or m_sendFlows.at(flowID)->isOpen())
		return false;

	return m_sendFlows.remove(flowID);
}

bool RTWebSocket::onFlowExceptionMessage(const uint8_t *bytes, const uint8_t *limit)
{
	const uint8_t *cursor = bytes;
	size_t rv;

	uintmax_t flowID = 0;
	cursor += (rv = rtmfp::VLU::parse(cursor, limit, &flowID));
	if(0 == rv)
		return false;

	uintmax_t reasonCode = 0;
	cursor += (rv = rtmfp::VLU::parse(cursor, limit, &reasonCode));
	if((0 == rv) and (cursor < limit))
		return false;

	// cursor..limit is the description, if any

	if(not m_sendFlows.has(flowID))
		return false;

	m_sendFlows.at(flowID)->onExceptionMessage(reasonCode, cursor, limit);

	return true;
}

void RTWebSocket::queueAck(std::shared_ptr<RecvFlow> recvFlow, bool immediate)
{
	if(m_open)
	{
		m_ackFlows.insert(recvFlow);
		if(immediate)
			scheduleAckNow();
	}
}

void RTWebSocket::scheduleAckNow()
{
	if(not m_ackNow)
	{
		m_ackNow = true;
		scheduleTransmission();
	}
}

void RTWebSocket::sendAcks()
{
	m_ackNow = false;
	for(auto each : m_ackFlows)
		each->sendAck();
	m_ackFlows.clear();
}

void RTWebSocket::queueTransmission(std::shared_ptr<SendFlow> flow)
{
	if(m_open and not m_transmissionWork[flow->getPriority()].find(flow))
		m_transmissionWork[flow->getPriority()].append(flow);
	scheduleTransmission();
}

void RTWebSocket::scheduleTransmission()
{
	if(m_open and not m_sendNow)
	{
		m_sendNow = true;
		m_adapter->notifyWhenWritable([this] { return transmit(); });
	}
}

bool RTWebSocket::transmit()
{
	if(not m_open)
		return false;

	if(m_ackNow)
	{
		sendAcks();
		return true;
	}

	if(getBytesInFlight() < outstandingThresh)
	{
		for(int pri = PRI_HIGHEST; pri >= PRI_LOWEST; pri--)
		{
			long name;
			auto &workQueue = m_transmissionWork[pri];

			while((name = workQueue.first()))
			{
				if(workQueue.at(name)->transmit(pri))
				{
					workQueue.moveNameToTail(name);
					startRTT();
					return true;
				}

				workQueue.remove(name);
			}
		}
	}

	m_sendNow = false;

	return false;
}

void RTWebSocket::startRTT()
{
	if((m_rttAnchor < 0.0) and (m_flowBytesSent >= m_rttPreviousPosition))
	{
		m_rttAnchor = getCurrentTime();
		m_rttPosition = m_flowBytesSent;

		size_t ackWin = std::max(MIN_ACK_WINDOW, (m_flowBytesSent - m_flowBytesAcked) / 4);
		ackWin = std::min(ackWin, MAX_ACK_WINDOW);

		Bytes msg;
		msg.push_back(MSG_ACK_WINDOW);
		rtmfp::VLU::append(ackWin, msg);
		sendBytes(msg);
	}
}

void RTWebSocket::measureRTT()
{
	if((m_rttAnchor >= 0.0) and (m_flowBytesAcked > m_rttPosition))
	{
		Time rtt = std::max(getCurrentTime() - m_rttAnchor, Time(0.0001));
		size_t numBytes = m_flowBytesSent - m_rttPreviousPosition;
		double bandwidth = numBytes / rtt;

		m_rttAnchor = -1.0;
		m_rttPreviousPosition = m_flowBytesSent;

		m_smoothedRTT = ((m_smoothedRTT * 7.0) + rtt) / 8.0;
		addRTT(rtt);

		size_t adjustThresh = std::max(MIN_ACK_WINDOW, outstandingThresh);
		if(numBytes >= adjustThresh - MIN_ACK_WINDOW)
			outstandingThresh = std::max(minOutstandingThresh, (size_t)(bandwidth * (getBaseRTT() + maxAdditionalDelay)));
	}
}

void RTWebSocket::addRTT(Time rtt)
{
	Time now = getCurrentTime();
	if(m_rttMeasurements.empty() or (now - m_rttMeasurements.front().origin > RTT_HISTORY_THRESH))
	{
		m_rttMeasurements.push_front({ rtt, now });

		while(not m_rttMeasurements.empty())
		{
			auto lastEntry = m_rttMeasurements.back();
			if(now - lastEntry.origin > RTT_HISTORY_THRESH * RTT_HISTORY_CAPACITY)
				m_rttMeasurements.pop_back();
			else
				break;
		}

		m_baseRTTCache = INFINITY;
		for(auto it = m_rttMeasurements.begin(); it != m_rttMeasurements.end(); it++)
			m_baseRTTCache = std::min(m_baseRTTCache, it->min_rtt);
	}
	else
		m_rttMeasurements.front().min_rtt = std::min(m_rttMeasurements.front().min_rtt, rtt);

	m_baseRTTCache = std::min(m_baseRTTCache, rtt);
}

void RTWebSocket::safeDoLater(Object *retainThis, const Task &task)
{
	if(m_open)
	{
		auto retaining = share_ref(retainThis);
		m_adapter->doLater([retaining, task] {
			task();
			(void)retaining;
		});
	}
}

void RTWebSocket::closeWithError()
{
	Task cb;
	swap(cb, onError);

	if(cb)
		cb();

	close();
}

// --- SendFlow

SendFlow::~SendFlow()
{
}

struct SendFlow::WriteMessage : public Object {
	Bytes m_bytes;  
	size_t m_offset { 0 };
	std::shared_ptr<IssuerWriteReceipt> m_receipt;

	WriteMessage(const uint8_t *bytes, const uint8_t *limit, std::shared_ptr<IssuerWriteReceipt> receipt) :
		m_bytes(bytes, limit),
		m_receipt(receipt)
	{}

	static size_t size_queue(const std::shared_ptr<WriteMessage> &value)
	{
		return value->m_bytes.size();
	}
};

SendFlow::SendFlow(std::shared_ptr<RTWebSocket> owner, uintmax_t flowID, uintmax_t *returnFlowID_ptr, const void *metadataBytes_, size_t metadataLen) :
	m_owner(owner),
	m_flowID(flowID),
	m_sendBuffer(WriteMessage::size_queue)
{
	const uint8_t *metadataBytes = (const uint8_t *)metadataBytes_;

	m_flowOpenMessage = std::make_shared<Bytes>();
	m_flowOpenMessage->push_back(returnFlowID_ptr ? MSG_FLOW_OPEN_RETURN : MSG_FLOW_OPEN);
	rtmfp::VLU::append(flowID, *m_flowOpenMessage);
	if(returnFlowID_ptr)
		rtmfp::VLU::append(*returnFlowID_ptr, *m_flowOpenMessage);
	m_flowOpenMessage->insert(m_flowOpenMessage->end(), metadataBytes, metadataBytes + metadataLen);
}

std::shared_ptr<WriteReceipt> SendFlow::write(const void *message, size_t len, Time startWithin, Time finishWithin)
{
	if(not m_open)
		return nullptr;

	auto receipt = share_ref(new IssuerWriteReceipt(m_owner->getCurrentTime(), startWithin, finishWithin), false);
	receipt->useCountUp();

	const uint8_t *messageBytes = (const uint8_t *)message;
	auto writeMessage = share_ref(new WriteMessage(messageBytes, messageBytes + len, receipt), false);

	m_sendBuffer.append(writeMessage);
	queueTransmission();

	return receipt;
}

std::shared_ptr<WriteReceipt> SendFlow::write(const Bytes &message, Time startWithin, Time finishWithin)
{
	return write(message.data(), message.size(), startWithin, finishWithin);
}

bool SendFlow::isOpen() const
{
	return m_open;
}

void SendFlow::close()
{
	auto myself = share_ref(this);

	if(not m_open)
		return;
	m_open = false;

	onException = nullptr;
	onRecvFlow = nullptr;

	queueTransmission();

	(void)myself;
}

Priority SendFlow::getPriority() const
{
	return m_priority;
}

void SendFlow::setPriority(Priority pri)
{
	bool changed = pri != m_priority;
	m_priority = pri;

	if(changed)
		queueTransmission();
}

bool SendFlow::isWritable() const
{
	return m_open and (getBufferedSize() < getBufferCapacity());
}

void SendFlow::notifyWhenWritable(const onwritable_f &onwritable)
{
	m_onwritable = onwritable;
	queueWritableNotify();
}

void SendFlow::setBufferCapacity(size_t bufferLengthInBytes)
{
	m_bufferCapacity = bufferLengthInBytes;
	queueWritableNotify();
}

size_t SendFlow::getBufferCapacity() const
{
	return m_bufferCapacity;
}

size_t SendFlow::getBufferedSize() const
{
	return m_sendBuffer.sum();
}

size_t SendFlow::getRecvBufferBytesAvailable() const
{
	return m_recvBufferBytesAvailable;
}

Time SendFlow::getUnsentAge() const
{
	for(long name = m_sendBuffer.first(); name > m_sendBuffer.SENTINEL; name = m_sendBuffer.next(name))
	{
		if(not m_sendBuffer.at(name)->m_receipt->isAbandoned())
			return m_owner->getCurrentTime() - m_sendBuffer.at(name)->m_receipt->createdAt();
	}
	return 0;
}

// --- SendFlow protected

void SendFlow::queueWritableNotify()
{
	if(m_onwritable and not m_writablePending)
	{
		m_writablePending = true;
		m_owner->safeDoLater(this, [this] { doWritable(); });
	}
}

void SendFlow::doWritable()
{
	m_writablePending = false;
	while(m_onwritable and isWritable())
	{
		if(not m_onwritable())
			m_onwritable = nullptr;
	}
}

bool SendFlow::transmit(int pri)
{
	if(pri != m_priority)
		return false;

	if(m_flowOpenMessage)
	{
		m_owner->sendBytes(*m_flowOpenMessage);
		m_flowOpenMessage.reset();
		return true;
	}

	trimSendBuffer();
	if(m_abandonCount > 0)
	{
		Bytes msg;
		msg.push_back(MSG_DATA_ABANDON);
		rtmfp::VLU::append(m_flowID, msg);
		if(m_abandonCount > 1)
			rtmfp::VLU::append(m_abandonCount - 1, msg);
		m_owner->sendBytes(msg);
		m_abandonCount = 0;
		return true;
	}

	if((not m_open) and m_sendBuffer.empty() and not m_sentClose)
	{
		Bytes msg;
		msg.push_back(MSG_FLOW_CLOSE);
		rtmfp::VLU::append(m_flowID, msg);
		m_owner->sendBytes(msg);
		m_sentClose = true;
		return true;
	}

	if(m_sentByteCount >= m_sendThroughAllowed)
		return false;

	return transmitOneFragment();
}

void SendFlow::queueTransmission()
{
	m_owner->queueTransmission(share_ref(this));
}

void SendFlow::trimSendBuffer()
{
	Time now = m_owner->getCurrentTime();

	while(not m_sendBuffer.empty())
	{
		auto &message = m_sendBuffer.firstValue();
		if(m_exception)
			message->m_receipt->abandon();
		else
			message->m_receipt->abandonIfNeeded(now);
		if(message->m_receipt->isAbandoned())
		{
			m_abandonCount++;
			message->m_receipt->useCountDown();
			m_sendBuffer.removeFirst();
		}
		else
			break;
	}
}

bool SendFlow::transmitOneFragment()
{
	if(m_sendBuffer.empty())
		return false;

	size_t chunkSize = std::min(MAX_CHUNK_SIZE, std::min(m_owner->chunkSize, m_sendThroughAllowed - m_sentByteCount));
	if(0 == chunkSize)
		return false; // should only happen if the user set a 0 chunk size, which is not useful

	auto &message = m_sendBuffer.firstValue();
	const uint8_t *data = message->m_bytes.data();
	size_t from = message->m_offset;
	size_t to = std::min(from + chunkSize, message->m_bytes.size());
	bool isLast = (to == message->m_bytes.size());

	Bytes fragmentMessage;
	fragmentMessage.push_back(isLast ? MSG_DATA_LAST : MSG_DATA_MORE);
	rtmfp::VLU::append(m_flowID, fragmentMessage);
	fragmentMessage.insert(fragmentMessage.end(), data + from, data + to);

	m_owner->sendBytes(fragmentMessage);
	m_sentByteCount += fragmentMessage.size();
	m_owner->m_flowBytesSent += fragmentMessage.size();

	message->m_offset = to;
	message->m_receipt->start();

	if(isLast)
	{
		message->m_receipt->useCountDown();
		m_sendBuffer.removeFirst();
		queueWritableNotify();
	}

	return true;
}

void SendFlow::onAck(uintmax_t deltaBytes, uintmax_t bufferAdvertisement)
{
	m_ackedPosition += deltaBytes;
	m_recvBufferBytesAvailable = bufferAdvertisement;
	m_sendThroughAllowed = m_ackedPosition + bufferAdvertisement;
	queueTransmission();
	queueWritableNotify();
}

void SendFlow::onExceptionMessage(uintmax_t reason, const uint8_t *description, const uint8_t *descriptionLimit)
{
	onException_f cb;
	swap(cb, onException);

	m_exception = true;
	close();

	if(cb)
		cb(reason, std::string((const char *)description, (const char *)descriptionLimit));

	trimSendBuffer(); // abandon all messages and notify
	queueTransmission();
}

// --- RecvFlow

RecvFlow::~RecvFlow()
{
}

struct RecvFlow::ReadMessage : public Object {
	uintmax_t m_messageNumber;
	std::vector<Bytes> m_fragments;
	size_t m_totalLength { 0 };
	bool m_complete { false };

	ReadMessage(uintmax_t messageNumber) : m_messageNumber (messageNumber)
	{}

	void addFragment(bool more, const uint8_t *bytes, const uint8_t *limit)
	{
		m_fragments.push_back(Bytes(bytes, limit));
		m_totalLength += limit - bytes;
		if(not more)
			m_complete = true;
	}

	void appendFullMessage(Bytes &dst)
	{
		dst.reserve(dst.size() + m_totalLength);
		for(auto it = m_fragments.begin(); it != m_fragments.end(); it++)
			dst.insert(dst.end(), it->begin(), it->end());
	}
};

RecvFlow::RecvFlow(std::shared_ptr<RTWebSocket> owner, uintmax_t flowID, const uint8_t *metadataBytes, const uint8_t *metadataLimit) :
	m_owner(owner),
	m_flowID(flowID),
	m_metadata(metadataBytes, metadataLimit)
{
}

bool RecvFlow::isOpen() const
{
	return m_open and m_userOpen;
}

void RecvFlow::accept()
{
	if(m_open)
		m_userOpen = true;
}

void RecvFlow::close()
{
	close(0);
}

void RecvFlow::close(uintmax_t reason)
{
	close(reason, "");
}

void RecvFlow::close(uintmax_t reason, const std::string &description)
{
	auto myself = share_ref(this);

	if(not m_open)
		return;
	m_userOpen = m_open = false;

	setBufferCapacity(0);
	onMessage = nullptr;
	onComplete = nullptr;

	if(m_complete)
		return;

	Bytes msg;
	msg.push_back(MSG_FLOW_EXCEPTION);
	rtmfp::VLU::append(m_flowID, msg);
	rtmfp::VLU::append(reason, msg);
	msg.insert(msg.end(), description.begin(), description.end());

	m_owner->sendBytes(msg); // send it right now
	
	(void)myself;
}

size_t RecvFlow::getBufferAdvertisement() const
{
	if(m_paused)
	{
		if(m_receiveBufferByteLength > m_bufferCapacity)
			return 0;
		return m_bufferCapacity - m_receiveBufferByteLength;
	}
	else
		return getBufferCapacity();
}

void RecvFlow::setBufferCapacity(size_t bufferLengthInBytes)
{
	if(bufferLengthInBytes != m_bufferCapacity)
		queueAck(true);
	m_bufferCapacity = bufferLengthInBytes;
}

size_t RecvFlow::getBufferCapacity() const
{
	return m_bufferCapacity;
}

size_t RecvFlow::getBufferedSize() const
{
	return m_receiveBufferByteLength;
}

void RecvFlow::setPaused(bool paused)
{
	bool wasPaused = m_paused;
	m_paused = paused;
	if(not paused)
	{
		queueDelivery();
		if(wasPaused)
			queueAck(true);
	}
}

bool RecvFlow::getPaused() const
{
	return m_paused;
}

Bytes RecvFlow::getMetadata() const
{
	return m_metadata;
}

std::shared_ptr<SendFlow> RecvFlow::openReturnFlow(const void *metadataBytes, size_t metadataLen, Priority pri)
{
	if(m_complete or not m_open)
		return nullptr;
	return m_owner->basicOpenFlow(metadataBytes, metadataLen, pri, &m_flowID);
}

std::shared_ptr<SendFlow> RecvFlow::openReturnFlow(const Bytes &metadata, Priority pri)
{
	return openReturnFlow(metadata.data(), metadata.size(), pri);
}

// --- RecvFlow protected

void RecvFlow::queueAck(bool immediate)
{
	m_owner->queueAck(share_ref(this), immediate);
}

void RecvFlow::sendAck()
{
	if(m_sentCloseAck)
		return;

	size_t advertisement = getBufferAdvertisement();
	m_ackThresh = advertisement / 2;

	Bytes ackMsg;
	ackMsg.push_back(MSG_DATA_ACK);
	rtmfp::VLU::append(m_flowID, ackMsg);
	rtmfp::VLU::append(m_receivedByteCount, ackMsg);
	rtmfp::VLU::append(advertisement, ackMsg);
	m_owner->sendBytes(ackMsg);

	m_receivedByteCount = 0;

	if(m_complete)
	{
		Bytes closeAck;
		closeAck.push_back(MSG_FLOW_CLOSE_ACK);
		rtmfp::VLU::append(m_flowID, closeAck);
		m_owner->sendBytes(closeAck);
		m_sentCloseAck = true;
	}
}

void RecvFlow::onFlowCloseMessage()
{
	m_complete = true;
	onDataAbandon(0);
	queueDelivery();
	queueAck(true);
}

void RecvFlow::onData(bool more, const uint8_t *bytes, const uint8_t *limit, size_t chunkLength)
{
	m_receivedByteCount += chunkLength;
	m_receiveBufferByteLength += limit - bytes;

	std::shared_ptr<ReadMessage> message;
	if(not m_receiveBuffer.empty())
		message = m_receiveBuffer.lastValue();
	if((not message) or message->m_complete)
	{
		message = share_ref(new ReadMessage(m_nextMessageNumber++), false);
		m_receiveBuffer.append(message);
	}

	message->addFragment(more, bytes, limit);
	if(not more)
		queueDelivery();

	queueAck(m_receivedByteCount >= m_ackThresh);
}

void RecvFlow::onDataAbandon(uintmax_t countMinusOne)
{
	uintmax_t count = countMinusOne + 1;
	if((not m_receiveBuffer.empty()) and not m_receiveBuffer.lastValue()->m_complete)
	{
		m_receiveBufferByteLength -= m_receiveBuffer.lastValue()->m_totalLength;
		m_receiveBuffer.removeLast();
		count--;
	}

	m_nextMessageNumber += count;

	queueAck(true);
}

void RecvFlow::queueDelivery()
{
	if((not m_deliveryPending) and (not m_paused))
	{
		m_deliveryPending = true;
		m_owner->safeDoLater(this, [this] { deliverData(); });
	}
}

void RecvFlow::deliverData()
{
	m_deliveryPending = false;

	while(not m_receiveBuffer.empty())
	{
		if(m_paused or not isOpen())
			break;

		auto message = m_receiveBuffer.firstValue();
		if(not message->m_complete)
			break;

		m_receiveBuffer.removeFirst();
		m_receiveBufferByteLength -= message->m_totalLength;

		if(onMessage)
		{
			Bytes buf;
			message->appendFullMessage(buf);
			onMessage(buf.data(), buf.size(), message->m_messageNumber);
		}
	}

	if(m_complete and m_receiveBuffer.empty())
		deliverCompleteAndClose();
}

void RecvFlow::deliverCompleteAndClose()
{
	if(not m_sentComplete)
	{
		m_sentComplete = true;
		if(isOpen() and onComplete)
			onComplete();
	}
	close();
}

} } } // namespace com::zenomt::rtmfp
