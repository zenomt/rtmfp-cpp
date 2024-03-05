// Copyright © 2022 Michael Thornburgh
// SPDX-License-Identifier: MIT

#include <cassert>

#include "../include/rtmfp/TCConnection.hpp"
#include "../include/rtmfp/URIParse.hpp"

namespace com { namespace zenomt {

namespace rtmp {

// TCConnection

TCConnection::TCConnection(int debugLevel) :
	m_debugLevel(debugLevel)
{
	if(m_debugLevel) printf("new TCConnection %p\n", (void *)this);
}

TCConnection::~TCConnection()
{
	if(m_debugLevel) printf("~TCConnection %p\n", (void *)this);
}

bool TCConnection::isOpen() const
{
	return m_userOpen and m_transportOpen;
}

bool TCConnection::isConnected() const
{
	return m_tcOpen and isOpen();
}

void TCConnection::close()
{
	basicClose(false);
}

bool TCConnection::connect(const Handler &onResult, const std::string &tcUrl, const AMF0Object *argObjectOrig, const Args &moreArgs)
{
	if((not m_userOpen) or (1.0 != m_nextTID)) // connect must be the first transaction, can only connect once
		return false;

	std::shared_ptr<AMF0> argObject;
	if(argObjectOrig)
		argObject = argObjectOrig->duplicate();
	else
		argObject = AMF0::Object();
	AMF0Object *argPtr = argObject->asObject();
	assert(argPtr);

	URIParse uri(tcUrl);

	if(not argPtr->getValueAtKey("tcUrl")->isString())
		argPtr->putValueAtKey(AMF0::String(uri.publicUri), "tcUrl");
	if(not argPtr->getValueAtKey("app")->isString())
		argPtr->putValueAtKey(AMF0::String(uri.path.substr(0, 1) == "/" ? uri.path.substr(1) : uri.path), "app");
	if(not argPtr->getValueAtKey("objectEncoding")->isNumber())
		argPtr->putValueAtKey(AMF0::Number(0), "objectEncoding");

	Args args;
	args.push_back(argObject);
	args.insert(args.end(), moreArgs.begin(), moreArgs.end());

	return basicTransact([this, onResult] (bool success, std::shared_ptr<AMF0> result) {
		onConnectResponse(success, result, onResult);
	}, "connect", args);
}

bool TCConnection::command(const std::string &command, const Args &args)
{
	if(not validateCommandName(command))
		return false;
	return basicCommand(command, 0, args);
}

bool TCConnection::transact(const Handler &onResult, const std::string &command, const Args &args)
{
	if((not validateCommandName(command)) or (1.0 == m_nextTID)) // must connect first
		return false;
	return basicTransact(onResult, command, args);
}

std::shared_ptr<TCStream> TCConnection::createStream()
{
	if(not m_userOpen)
		return nullptr;

	auto netStream = share_ref(new TCStream(share_ref(this)), false);

	basicTransact([this, netStream] (bool success, std::shared_ptr<AMF0> result) {
		if(  (success)
		 and (result)
		 and (result->doubleValue() > 0)
		 and (result->doubleValue() <= double(UINT32_MAX))
		 and (0 == m_netStreams.count(uint32_t(result->doubleValue())))
		)
		{
			uint32_t streamID = uint32_t(result->doubleValue());
			m_netStreams[streamID] = netStream;
			if(not netStream->setStreamID(streamID))
				deleteStream(streamID); // closed while transaction was inflight
		}
		else
		{
			netStream->deleteStream();
			basicClose(true);
		}
	}, "createStream", { AMF0::Null() });

	return netStream;
}

std::shared_ptr<AMF0> TCConnection::firstArg(const Args &args)
{
	return args.empty() ? nullptr : args[0];
}

std::shared_ptr<AMF0> TCConnection::safeFirstArg(const Args &args)
{
	return args.empty() ? AMF0::Undefined() : args[0];
}

// ---

std::shared_ptr<WriteReceipt> TCConnection::write(uint32_t streamID, uint8_t messageType, uint32_t timestamp, const Bytes &payload, Time startWithin, Time finishWithin)
{
	return write(streamID, messageType, timestamp, payload.data(), payload.size(), startWithin, finishWithin);
}

void TCConnection::onMessage(uint32_t streamID, uint8_t messageType, uint32_t timestamp, const uint8_t *payload, size_t len)
{
	if(m_debugLevel > 1)
		printf("TCConnection %p onMessage streamID %u type %d timestamp %u len %zu\n", (void *)this, (unsigned)streamID, messageType, (unsigned)timestamp, len);

	switch(messageType)
	{
	case TCMSG_COMMAND:
	case TCMSG_COMMAND_EX:
		onCommandMessage(streamID, messageType, payload, len);
		break;

	case TCMSG_AUDIO:
	case TCMSG_VIDEO:
	case TCMSG_DATA:
	case TCMSG_DATA_EX:
		if(streamID)
			onStreamMessage(streamID, messageType, timestamp, payload, len);
		break;

	case TCMSG_USER_CONTROL:
		onUserControlMessage(payload, len);
		break;

	default:
		break;
	}
}

void TCConnection::onCommandMessage(uint32_t streamID, uint8_t messageType, const uint8_t *payload, size_t len)
{
	const uint8_t *cursor = payload;
	const uint8_t *limit = cursor + len;

	if(0 == len)
		return;
	if((TCMSG_COMMAND_EX == messageType) and (0 != *cursor++)) // COMMAND_EX has a format id, and only format id=0 is defined
		return;

	if(m_debugLevel)
	{
		printf("TCConnection %p onCommandMessage streamID %u type %d len %zu\n", (void *)this, (unsigned)streamID, messageType, len);
		Args args;
		AMF0::decode(cursor, limit, args);
		for(auto it = args.begin(); it != args.end(); it++)
			printf("  %s\n", (*it)->repr().c_str());
	}

	auto command = AMF0::decode(&cursor, limit);
	auto tid = AMF0::decode(&cursor, limit);
	auto arg = AMF0::decode(&cursor, limit); // not used in this direction, but present

	Args args;
	AMF0::decode(cursor, limit, args);

	if((not command) or (not command->isString()) or (not tid) or (not tid->isNumber()))
	{
		if(m_debugLevel) printf("  invalid command format, closing\n");

		basicClose(true);
		return;
	}

	if(0 == streamID)
		onControlCommand(command->stringValue(), tid->doubleValue(), args);
	else
		onStreamCommand(streamID, command->stringValue(), args);
}

void TCConnection::onControlCommand(const std::string &command, double transactionID, const Args &args)
{
	if((command == "_result") or (command == "_error"))
		onTransactionResponse(command == "_result", transactionID, args);
	else if(command == "onStatus")
		onControlStatusMessage(safeFirstArg(args));
	else if(onCommand)
		onCommand(command, args);
}

void TCConnection::onControlStatusMessage(std::shared_ptr<AMF0> info)
{
	if(onStatus)
		onStatus(info);
}

void TCConnection::onStreamCommand(uint32_t streamID, const std::string &command, const Args &args)
{
	auto it = m_netStreams.find(streamID);
	if(it != m_netStreams.end())
		it->second->onCommandMessage(command, args);
}

void TCConnection::onStreamMessage(uint32_t streamID, uint8_t messageType, uint32_t timestamp, const uint8_t *payload, size_t len)
{
	auto it = m_netStreams.find(streamID);
	if(it != m_netStreams.end())
		it->second->onStreamMessage(messageType, timestamp, payload, len);
}

void TCConnection::onUserControlMessage(const uint8_t *payload, size_t len)
{
	// default ignore
}

void TCConnection::basicClose(bool isError)
{
	if(m_debugLevel) printf("basicClose isError: %s\n", isError ? "yes" : "no");

	if(not m_userOpen)
		return;
	m_userOpen = false;

	if(isError and not m_tcOpen)
		onControlStatusMessage(share_ref(AMF0::Object()
			->putValueAtKey(AMF0::String("error"), "level")
			->putValueAtKey(AMF0::String("NetConnection.Connect.Failed"), "code")
		));
	else
		onControlStatusMessage(share_ref(AMF0::Object()
			->putValueAtKey(AMF0::String("status"), "level")
			->putValueAtKey(AMF0::String("NetConnection.Connect.Closed"), "code")
		));

	Task tmpOnClose;
	swap(tmpOnClose, onClose);
	onTransportOpen = nullptr;
	onStatus = nullptr;
	onCommand = nullptr;

	for(auto it = m_transactions.begin(); it != m_transactions.end(); it++)
		if(it->second)
			it->second(false, nullptr);
	m_transactions.clear();

	auto netStreamsCopy = m_netStreams;
	for(auto it = netStreamsCopy.begin(); it != netStreamsCopy.end(); it++)
		it->second->deleteStream();
	assert(m_netStreams.empty());

	if(tmpOnClose)
		tmpOnClose();
}

bool TCConnection::basicCommand(const std::string &command, double transactionID, const Args &args)
{
	if(m_debugLevel)
	{
		printf("TCConnection %p TCMSG_COMMAND %s tid %f\n", (void *)this, command.c_str(), transactionID);
		for(auto it = args.begin(); it != args.end(); it++)
			if(*it)
				printf("  %s\n", (*it)->repr().c_str());
	}

	return !! write(0, TCMSG_COMMAND, 0, Message::command(command.c_str(), transactionID, args), INFINITY, INFINITY);
}

bool TCConnection::basicTransact(const Handler &onResult, const std::string &command, const Args &args)
{
	double tid = m_nextTID++;
	if(basicCommand(command, tid, args))
	{
		m_transactions[tid] = onResult;
		return true;
	}
	return false;
}

void TCConnection::onTransactionResponse(bool success, double transactionID, const Args &args)
{
	auto it = m_transactions.find(transactionID);
	if(it != m_transactions.end())
	{
		Handler handler;
		swap(handler, it->second);
		m_transactions.erase(it);
		if(handler)
			handler(success, safeFirstArg(args));
	}
}

void TCConnection::onConnectResponse(bool success, std::shared_ptr<AMF0> result, const Handler &onResult)
{
	m_tcOpen = success;

	if(onResult)
		onResult(success, result);
	onControlStatusMessage(result);

	if(not success)
		basicClose(true);
}

void TCConnection::deleteStream(uint32_t streamID)
{
	if(m_netStreams.count(streamID))
	{
		basicCommand("deleteStream", 0, { AMF0::Null(), AMF0::Number(streamID) });
		m_netStreams.erase(streamID);
	}
}

bool TCConnection::validateCommandName(const std::string &command)
{
	if( (command == "createStream")
	 or (command == "deleteStream")
	 or (command == "connect")
	)
		return false;

	return m_userOpen;
}

void TCConnection::syncStream(uint32_t streamID)
{
	// transport-specific to override
}

// TCStream

TCStream::TCStream(std::shared_ptr<TCConnection> owner) :
	m_owner(owner)
{
	if(m_owner->m_debugLevel) printf("new TCStream %p\n", (void *)this);
}

TCStream::~TCStream()
{
	if(m_owner->m_debugLevel) printf("~TCStream %p\n", (void *)this);
}

bool TCStream::isOpen() const
{
	return m_userOpen and m_streamID;
}

void TCStream::deleteStream()
{
	m_userOpen = false;

	onOpen = nullptr;
	onStatus = nullptr;
	onData = nullptr;
	onAudio = nullptr;
	onVideo = nullptr;

	if(m_streamID)
		m_owner->deleteStream(m_streamID);
	m_streamID = 0;

	expireChain(INFINITY);
}

void TCStream::closeStream()
{
	queueCommand("closeStream", nullptr, {});
}

void TCStream::chain(std::shared_ptr<WriteReceipt> receipt)
{
	m_chain.append(receipt);
}

void TCStream::expireChain(Time deadline)
{
	expireChain(deadline, deadline);
}

void TCStream::expireChain(Time startDeadline, Time finishDeadline)
{
	m_chain.expire(startDeadline, finishDeadline);
}

void TCStream::publish(const std::string &name, const Args &args)
{
	queueCommand("publish", AMF0::String(name), args);
}

std::shared_ptr<WriteReceipt> TCStream::send(const std::string &command, const Args &args)
{
	return send(0, command, args);
}

std::shared_ptr<WriteReceipt> TCStream::send(uint32_t timestamp, const std::string &command, const Args &args)
{
	if(0 == m_streamID)
		return nullptr;

	Bytes msg;
	AMF0String(command).encode(msg);
	AMF0::encode(args, msg);
	return m_owner->write(m_streamID, TCMSG_DATA, 0, msg, INFINITY, INFINITY);
}

std::shared_ptr<WriteReceipt> TCStream::sendAudio(uint32_t timestamp, const void *bytes, size_t len, Time startWithin, Time finishWithin)
{
	if(0 == m_streamID)
		return nullptr;
	return m_owner->write(m_streamID, TCMSG_AUDIO, timestamp, bytes, len, startWithin, finishWithin);
}

std::shared_ptr<WriteReceipt> TCStream::sendAudio(uint32_t timestamp, const Bytes &bytes, Time startWithin, Time finishWithin)
{
	return sendAudio(timestamp, bytes.data(), bytes.size(), startWithin, finishWithin);
}

std::shared_ptr<WriteReceipt> TCStream::sendVideo(uint32_t timestamp, const void *bytes, size_t len, Time startWithin, Time finishWithin)
{
	if(0 == m_streamID)
		return nullptr;
	return m_owner->write(m_streamID, TCMSG_VIDEO, timestamp, bytes, len, startWithin, finishWithin);
}

std::shared_ptr<WriteReceipt> TCStream::sendVideo(uint32_t timestamp, const Bytes &bytes, Time startWithin, Time finishWithin)
{
	return sendVideo(timestamp, bytes.data(), bytes.size(), startWithin, finishWithin);
}

void TCStream::sync()
{
	if(m_streamID)
		m_owner->syncStream(m_streamID);
}

void TCStream::play(const std::string &name, const Args &args)
{
	queueCommand("play", AMF0::String(name), args);
}

void TCStream::pause(bool paused)
{
	queueCommand("pause", AMF0::Boolean(paused), {});
}

void TCStream::receiveAudio(bool shouldReceive)
{
	queueCommand("receiveAudio", AMF0::Boolean(shouldReceive), {});
}

void TCStream::receiveVideo(bool shouldReceive)
{
	queueCommand("receiveVideo", AMF0::Boolean(shouldReceive), {});
}

// ---

bool TCStream::setStreamID(uint32_t streamID)
{
	if(m_userOpen)
	{
		m_streamID = streamID;

		Task tmpOnOpen;
		swap(tmpOnOpen, onOpen);
		if(tmpOnOpen)
			tmpOnOpen();

		flushCommands();
	}
	return m_userOpen;
}

void TCStream::onCommandMessage(const std::string &command, const Args &args)
{
	if(command == "onStatus")
	{
		if(onStatus)
			onStatus(TCConnection::safeFirstArg(args));
	}
}

void TCStream::onStreamMessage(uint8_t messageType, uint32_t timestamp, const uint8_t *payload, size_t len)
{
	switch(messageType)
	{
	case TCMSG_AUDIO:
		if(onAudio)
			onAudio(timestamp, payload, len);
		break;

	case TCMSG_VIDEO:
		if(onVideo)
			onVideo(timestamp, payload, len);
		break;

	case TCMSG_DATA_EX:
	case TCMSG_DATA:
		onDataMessage(messageType, timestamp, payload, len);
		break;

	default:
		break;
	}
}

void TCStream::onDataMessage(uint8_t messageType, uint32_t timestamp, const uint8_t *payload, size_t len)
{
	const uint8_t *cursor = payload;
	const uint8_t *limit = cursor + len;

	if((TCMSG_DATA_EX == messageType) and (0 != *cursor++))
		return; // only format 0 is defined

	auto command = AMF0::decode(&cursor, limit);
	Args args;
	AMF0::decode(cursor, limit, args);

	if(command and command->isString())
	{
		if(m_owner->m_debugLevel)
		{
			printf("TCStream %p onData command %s\n", (void *)this, command->stringValue());
			for(auto it = args.begin(); it != args.end(); it++)
				printf("  %s\n", (*it)->repr().c_str());
		}

		if(onData)
			onData(timestamp, command->stringValue(), args);
	}
}

void TCStream::queueCommand(const std::string &command, std::shared_ptr<AMF0> insertArg, const Args &args)
{
	if(m_owner->m_debugLevel > 1)
	{
		printf("TCStream %p (%u%s) queue command %s\n", (void *)this, m_streamID, m_streamID ? "" : " unallocated", command.c_str());
		if(insertArg)
			printf("  %s\n", insertArg->repr().c_str());
		for(auto it = args.begin(); it != args.end(); it++)
			if(*it)
				printf("  %s\n", (*it)->repr().c_str());
	}

	Bytes msg;
	AMF0String(command).encode(msg);
	AMF0Number(0).encode(msg);
	AMF0Null().encode(msg);
	if(insertArg)
		insertArg->encode(msg);
	AMF0::encode(args, msg);
	m_pendingCommands.push(msg);
	flushCommands();
}

void TCStream::flushCommands()
{
	if(m_streamID)
	{
		while(not m_pendingCommands.empty())
		{
			m_owner->write(m_streamID, TCMSG_COMMAND, 0, m_pendingCommands.front(), INFINITY, INFINITY);
			m_pendingCommands.pop();
		}
	}
}

} // namespace rtmp

namespace rtmfp {

using namespace com::zenomt::rtmp;

// RTMFPTCConnection

bool RTMFPTCConnection::init(RTMFP *rtmfp, const Bytes &epd)
{
	if(m_rtmfp or not rtmfp)
		return false;

	m_rtmfp = rtmfp;
	m_controlSend = m_rtmfp->openFlow(epd, TCMetadata::encode(0, RO_SEQUENCE), PRI_IMMEDIATE);
	if(not m_controlSend)
		return false;

	auto myself = share_ref(this);
	m_controlSend->onWritable = [this, myself] {
		m_transportOpen = true;
		if(m_userOpen)
		{
			m_sessionOptFlow = m_controlSend->openFlow({});
			if(onTransportOpen)
				onTransportOpen();
		}
		return false;
	};
	m_controlSend->notifyWhenWritable();
	m_controlSend->onException = [this] (uintmax_t reason) { basicClose(true); };
	m_controlSend->onRecvFlow = [this] (std::shared_ptr<RecvFlow> flow) { acceptFlow(flow); };

	return true;
}

void RTMFPTCConnection::addCandidateAddress(const Address &addr, Time delay)
{
	if(m_controlSend)
		m_controlSend->addCandidateAddress(addr, delay);
}

void RTMFPTCConnection::addCandidateAddress(const struct sockaddr *addr, Time delay)
{
	if(m_controlSend)
		m_controlSend->addCandidateAddress(addr, delay);
}

void RTMFPTCConnection::addCandidateAddresses(const std::vector<Address> &addrs)
{
	for(auto it = addrs.begin(); it != addrs.end(); it++)
		addCandidateAddress(*it, 0);
}

bool RTMFPTCConnection::refreshSession()
{
	return !! write(0, 0, 0, nullptr, 0, -1, -1);
}

Flow * RTMFPTCConnection::sessionOpt() const
{
	return m_sessionOptFlow.get();
}

Bytes RTMFPTCConnection::getServerFingerprint() const
{
	if(m_sessionOptFlow)
	{
		auto epd = m_sessionOptFlow->getFarCanonicalEPD();
		if((epd.size() == 34) and (0x21 == epd[0]) and (0x0f == epd[1])) // RFC 7425 §4.4.4
			return Bytes(epd.data() + 2, epd.data() + epd.size());
		return epd;
	}
	return {};
}

// ---

std::shared_ptr<WriteReceipt> RTMFPTCConnection::write(uint32_t streamID, uint8_t messageType, uint32_t timestamp, const void *payload, size_t len, Time startWithin, Time finishWithin)
{
	if(m_debugLevel > 1)
		printf("RTMFPTCConnection %p write streamID %u type %d timestamp %u len %zu\n", (void *)this, (unsigned)streamID, messageType, (unsigned)timestamp, len);

	if(0 == streamID)
		return m_controlSend->write(TCMessage::message(messageType, timestamp, (const uint8_t *)payload, len), startWithin, finishWithin);

	auto &stream = m_netStreamTransports[streamID]; // create on demand
	return stream.write(m_controlRecv, streamID, messageType, timestamp, (const uint8_t *)payload, len, startWithin, finishWithin);
}

void RTMFPTCConnection::acceptFlow(std::shared_ptr<RecvFlow> flow)
{
	uint32_t streamID = 0;
	ReceiveOrder rxOrder = RO_SEQUENCE;

	if(not TCMetadata::parse(flow->getMetadata(), &streamID, &rxOrder)) // only TC flows for now
		return;

	flow->setBufferCapacity((1<<24) - 1024); // 16MB, big enough for largest TCMessage

	if(not m_controlRecv)
	{
		if(0 != streamID)
		{
			basicClose(true);
			return;
		}
		m_controlRecv = flow;
		m_controlRecv->onComplete = [this] (bool error) { basicClose(error); };
		setOnMessage(m_controlRecv, 0, nullptr);

		flow->accept();

		return;
	}

	if(streamID and not m_netStreams.count(streamID))
		return; // reject if not for an active streamID

	flow->setReceiveOrder(rxOrder);

	std::shared_ptr<ReorderBuffer> reorderBuffer;
	if(RO_NETWORK == rxOrder)
		reorderBuffer = reorderBufferFactory(reorderWindowPeriod);

	flow->onComplete = [this, flow, reorderBuffer, streamID] (bool error) {
		if(reorderBuffer)
			reorderBuffer->flush();
		m_netStreamTransports[streamID].m_recvFlows.erase(flow);
	};

	setOnMessage(flow, streamID, reorderBuffer);
	flow->accept();
	m_netStreamTransports[streamID].m_recvFlows.insert(flow);
}

void RTMFPTCConnection::setOnMessage(std::shared_ptr<RecvFlow> flow, uint32_t streamID, std::shared_ptr<ReorderBuffer> reorderBuffer)
{
	if(reorderBuffer)
	{
		reorderBuffer->onMessage = [this, streamID] (const uint8_t *bytes, size_t len, uintmax_t sequenceNumber, size_t fragmentCount, bool isLate) {
			if((not isLate) or shouldAlwaysDeliver(bytes, len))
				deliverMessage(streamID, bytes, len);
		};
	}

	flow->onMessage = [this, streamID, flow, reorderBuffer] (const uint8_t *bytes, size_t len, uintmax_t sequenceNumber, size_t fragmentCount) {
		uint32_t syncID = 0;
		size_t count = 0;
		if(FlowSyncManager::parse(bytes, len, syncID, count))
		{
			m_syncManager.sync(syncID, count, flow);
			len = 0; // allow accounting for sequence numbers in reorder buffer; deliverMessage will drop empties
		}

		if(reorderBuffer)
		{
			reorderBuffer->insert(bytes, len, sequenceNumber, fragmentCount);
			reorderBuffer->deliverThrough(flow->getCumulativeAckSequenceNumber());
		}
		else
			deliverMessage(streamID, bytes, len);
	};
}

void RTMFPTCConnection::deliverMessage(uint32_t streamID, const uint8_t *bytes, size_t len)
{
	uint8_t messageType = 0;
	uint32_t timestamp = 0;
	size_t rv = TCMessage::parseHeader(bytes, bytes + len, &messageType, &timestamp);
	if(rv)
		onMessage(streamID, messageType, timestamp, bytes + rv, len - rv);
}

bool RTMFPTCConnection::shouldAlwaysDeliver(const uint8_t *bytes, size_t len)
{
	uint8_t messageType = 0;
	size_t rv = TCMessage::parseHeader(bytes, bytes + len, &messageType, nullptr);
	if(not rv)
		return false;

	switch(messageType)
	{
	case TCMSG_VIDEO: return Message::isVideoSequenceSpecial(bytes + rv, len - rv);
	case TCMSG_AUDIO: return Message::isAudioSequenceSpecial(bytes + rv, len - rv);
	default: return true;
	}
}

void RTMFPTCConnection::basicClose(bool isError)
{
	TCConnection::basicClose(isError);

	if(m_controlSend) m_controlSend->close();
	if(m_controlRecv) m_controlRecv->close();
	if(m_sessionOptFlow) m_sessionOptFlow->close();

	m_netStreamTransports.clear(); // catch leftovers including for streamID 0
}

void RTMFPTCConnection::deleteStream(uint32_t streamID)
{
	TCConnection::deleteStream(streamID);
	m_netStreamTransports.erase(streamID);
}

void RTMFPTCConnection::syncStream(uint32_t streamID)
{
	auto &stream = m_netStreamTransports[streamID];

	stream.openFlowForType(m_controlRecv, streamID, TCMSG_VIDEO);
	stream.openFlowForType(m_controlRecv, streamID, TCMSG_AUDIO);
	stream.openFlowForType(m_controlRecv, streamID, TCMSG_DATA);

	stream.sync(m_nextSyncID++);
}

void RTMFPTCConnection::onUserControlMessage(const uint8_t *payload, size_t len)
{
	if(len < 2)
		return;

	uint16_t type = (payload[0] << 8) + payload[1];
	switch(type)
	{
	case TC_USERCONTROL_SET_KEEPALIVE:
		onSetKeepaliveUserCommand(payload, len);
		break;

	default:
		break;
	}
}

void RTMFPTCConnection::onSetKeepaliveUserCommand(const uint8_t *payload, size_t len)
{
	if((len < 10) or ignoreSetKeepaliveUserCommand)
		return;

	uint32_t serverPeriodMsec = (payload[2] << 24) + (payload[3] << 16) + (payload[4] << 8) + payload[5];
	uint32_t peerPeriodMsec = (payload[6] << 24) + (payload[7] << 16) + (payload[8] << 8) + payload[9];

	serverPeriodMsec = std::max(serverPeriodMsec, uint32_t(5000)); // RFC 7425 §5.3.4
	peerPeriodMsec = std::max(serverPeriodMsec, uint32_t(5000)); // RFC 7425 §5.3.4

	m_controlRecv->setSessionKeepalivePeriod(serverPeriodMsec / 1000.0);
	m_rtmfp->setDefaultSessionKeepalivePeriod(peerPeriodMsec / 1000.0);
}

// RTMFPTCConnection::NetStreamTransport

RTMFPTCConnection::NetStreamTransport::~NetStreamTransport()
{
	if(m_video) m_video->close();
	if(m_audio) m_audio->close();
	if(m_data) m_data->close();

	for(auto it = m_recvFlows.begin(); it != m_recvFlows.end(); it++)
		(*it)->close();
}

SendFlow * RTMFPTCConnection::NetStreamTransport::openFlowForType(const std::shared_ptr<RecvFlow> &control, uint32_t streamID, uint8_t messageType)
{
	Priority pri = PRI_IMMEDIATE;
	ReceiveOrder rxIntent = RO_SEQUENCE;
	std::shared_ptr<SendFlow> *flowRef = &m_data;

	if(TCMSG_VIDEO == messageType)
	{
		flowRef = &m_video;
		pri = PRI_PRIORITY; // lower than audio/data but still time-critical
	}
	else if(TCMSG_AUDIO == messageType)
		flowRef = &m_audio;

	if(not *flowRef)
		*flowRef = control->openReturnFlow(TCMetadata::encode(streamID, rxIntent), pri);

	return flowRef->get();
}

std::shared_ptr<WriteReceipt> RTMFPTCConnection::NetStreamTransport::write(const std::shared_ptr<RecvFlow> &control, uint32_t streamID, uint8_t messageType, uint32_t timestamp, const uint8_t *payload, size_t len, Time startWithin, Time finishWithin)
{
	SendFlow *flow = openFlowForType(control, streamID, messageType);
	if(not flow)
		return nullptr;
	return flow->write(TCMessage::message(messageType, timestamp, payload, len), startWithin, finishWithin);
}

void RTMFPTCConnection::NetStreamTransport::sync(uint32_t syncID)
{
	uint32_t count = 0;
	if(m_video) count++;
	if(m_audio) count++;
	if(m_data) count++;

	Bytes message = FlowSyncManager::makeSyncMessage(syncID, count);

	if(m_video) m_video->write(message, INFINITY, INFINITY);
	if(m_audio) m_audio->write(message, INFINITY, INFINITY);
	if(m_data) m_data->write(message, INFINITY, INFINITY);
}

} // namespace rtmfp

} } // namespace com::zenomt
