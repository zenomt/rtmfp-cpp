// Copyright © 2021 Michael Thornburgh
// SPDX-License-Identifier: MIT

// TODO:
//  * don't relay setPeerInfo
//  * happy eyeballs for RTMP (handle multiple addresses from getaddrinfo))
//  * use URIs for dest
//    - rewrite connect tcUrl
//  * RTMPS (at least output)

#include <cassert>
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>

extern "C" {
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
}

#include "rtmfp/rtmfp.hpp"
#include "rtmfp/RunLoops.hpp"
#include "rtmfp/FlashCryptoAdapter_OpenSSL.hpp"
#include "rtmfp/PerformerPosixPlatformAdapter.hpp"
#include "rtmfp/TCMessage.hpp"
#include "rtmfp/FlowSyncManager.hpp"
#include "rtmfp/ReorderBuffer.hpp"
#include "rtmfp/RedirectorClient.hpp"
#include "rtmfp/Hex.hpp"

#include "RTMP.hpp"
#include "PosixStreamPlatformAdapter.hpp"
#include "redirectorspec.hpp"
#include "RTWebSocket.hpp"
#include "SimpleWebSocket.hpp"
#include "SimpleWebSocketMessagePlatformAdapter.hpp"

using namespace com::zenomt;
using namespace com::zenomt::rtmfp;
using namespace com::zenomt::rtmp;
using namespace com::zenomt::websock;
// need to keep rtws:: qualifier to avoid collisions with RTMFP SendFlow/RecvFlow.

namespace {

class Connection; class Client;

enum Protocol { PROTO_UNSPEC, PROTO_RTMP, PROTO_RTMP_SIMPLE, PROTO_RTWS, PROTO_RTMFP };

enum {
	TC_VIDEO_COMMAND_RANDOM_ACCESS_CHECKPOINT = 3
};

int verbose = 0;
int port = 1935;
bool requireHMAC = true;
bool requireSSEQ = true;
bool interleave = false;
bool sendVideoCheckpoint = false;
bool replayCheckpointFrame = true;
bool collapseAudioGaps = false;
Time videoLifetime = 2.0;
Time audioLifetime = 2.2;
Time finishByMargin = 0.1;
Time previousGopStartByMargin = 0.1;
Time checkpointLifetime = 4.5;
Time reorderWindowPeriod = 1.0;
Time delaycc_delay = INFINITY;
ReceiveOrder mediaReceiveIntent = RO_SEQUENCE;
bool expirePreviousGop = true;
bool interrupted = false;
bool stopping = false;
Protocol inputProtocol = PROTO_UNSPEC;
Protocol outputProtocol = PROTO_UNSPEC;
const char *desthostname = nullptr;
const char *destservname = "1935";
const char *overrideRtmfpUri = nullptr;
const char *backupRtmfpUri = "rtmfp:";
int dscp = 0;

PreferredRunLoop mainRL;
Performer mainPerformer(&mainRL);
PreferredRunLoop workerRL;
Performer workerPerformer(&workerRL);
PreferredRunLoop lookupRL;
Performer lookupPerformer(&lookupRL);

std::set<std::shared_ptr<Client>> clients;

void lookup(const std::function<void(const std::vector<Address> &results)> &onresult)
{
	lookupPerformer.perform([onresult] {
		int error = 0;
		auto results = Address::lookup(desthostname, destservname, &error);
		if(error)
			printf("address lookup: %s\n", gai_strerror(error));
		mainPerformer.perform([onresult, results] { onresult(results); });
	});
}

class Connection : public Object {
public:
	~Connection()
	{
		if(verbose > 1) printf("~Connection %p\n", (void *)this);
	}

	virtual void close()
	{
		if(m_open)
		{
			if(verbose and (m_videoMessages or m_audioMessages or m_videoMessagesLate or m_audioMessagesLate))
				printf("Connection %p video abn %lu/%lu (%lu late)  audio abn %lu/%lu (%lu late)\n", (void *)this, (unsigned long)m_videoMessagesAbandoned, (unsigned long)m_videoMessages, (unsigned long)m_videoMessagesLate, (unsigned long)m_audioMessagesAbandoned, (unsigned long)m_audioMessages, (unsigned long)m_audioMessagesLate);
		}
		m_open = false;
	}

	virtual void shutdown() = 0;

	bool isFinished() const { return m_finished; }

	std::shared_ptr<WriteReceipt> write(uint32_t streamID, uint8_t messageType, uint32_t timestamp, const void *payload, size_t len)
	{
		const uint8_t *data = (const uint8_t *)payload;
		Time startWithin = INFINITY;
		bool isVideoCodingLayer = false;
		auto &streamState = m_streamStates[streamID];

		if(collapseAudioGaps)
		{
			uint32_t adjustedTimestamp = timestamp ? timestamp - streamState.m_timestampShift : 0;
			if(TCMSG_AUDIO == messageType)
			{
				uint32_t lastTS = streamState.m_lastAudioTimestamp;
				if(adjustedTimestamp and lastTS and Message::timestamp_gt(adjustedTimestamp, lastTS + 1536/48)) // XXX 48kHz AAC only
				{
					streamState.m_timestampShift = (timestamp - lastTS) - 1024/48; // XXX need real audio frame duration
					adjustedTimestamp = timestamp - streamState.m_timestampShift;
					if(verbose) printf("Connection %p stream %lu new timestamp shift %lu at %lu\n", (void *)this, (unsigned long)streamID, (unsigned long)(streamState.m_timestampShift), (unsigned long)adjustedTimestamp);
				}
			}
			timestamp = adjustedTimestamp;
		}

		switch(messageType)
		{
		case TCMSG_VIDEO:
			if(collapseAudioGaps and Message::timestamp_lt(timestamp, streamState.m_lastVideoTimestamp))
				timestamp = streamState.m_lastVideoTimestamp + 5;
			streamState.m_lastVideoTimestamp = timestamp;
			if(isVideoCheckpointCommand(data, len))
			{
				if(replayCheckpointFrame)
				{
					if(Message::timestamp_gt(timestamp, streamState.m_lastKeyframeTimestamp) and streamState.m_lastKeyframe.size())
					{
						write(streamID, TCMSG_VIDEO, timestamp, streamState.m_lastKeyframe.data(), streamState.m_lastKeyframe.size());
						if(verbose) printf("Connection %p stream %lu replay keyframe at %lu\n", (void *)this, (unsigned long)streamID, (unsigned long)timestamp);
					}
					return nullptr;
				}
				else
					startWithin = checkpointLifetime; // forward (or delete if checkpointLifetime < 0)
			}
			else if(not isVideoSequenceSpecial(data, len))
			{
				startWithin = videoLifetime;
				isVideoCodingLayer = true;
			}
			break;

		case TCMSG_AUDIO:
			streamState.m_lastAudioTimestamp = timestamp;
			if(not isAudioSequenceSpecial(data, len))
				startWithin = audioLifetime;
			break;
		}

		Time finishWithin = startWithin + finishByMargin;

		auto rv = basicWrite(streamID, messageType, timestamp, data, len, startWithin, finishWithin);

		if(rv and isVideoCodingLayer)
		{
			if(Message::isVideoKeyframe(data, len))
			{
				streamState.m_chain.expire(
					expirePreviousGop ? mainRL.getCurrentTime() + previousGopStartByMargin : INFINITY,
					expirePreviousGop ? mainRL.getCurrentTime() + finishByMargin : INFINITY);

				if(replayCheckpointFrame)
				{
					streamState.m_lastKeyframe = Bytes(data, data + len);
					streamState.m_lastKeyframeTimestamp = timestamp;
				}

				if(sendVideoCheckpoint)
				{
					uint8_t command[] = { TC_VIDEO_FRAMETYPE_COMMAND | TC_VIDEO_CODEC_NONE, TC_VIDEO_COMMAND_RANDOM_ACCESS_CHECKPOINT };
					basicWrite(streamID, TCMSG_VIDEO, timestamp, command, sizeof(command), checkpointLifetime, checkpointLifetime);
				}
			}

			if(startWithin < INFINITY)
				streamState.m_chain.append(rv);
		}

		if(rv and verbose)
			rv->onFinished = [messageType, this] (bool abandoned) {
				if(abandoned)
				{
					printf("-");
					fflush(stdout);
				}

				switch(messageType)
				{
				case TCMSG_VIDEO:
					m_videoMessages++;
					if(abandoned)
						m_videoMessagesAbandoned++;
					break;
				case TCMSG_AUDIO:
					m_audioMessages++;
					if(abandoned)
						m_audioMessagesAbandoned++;
					break;
				default:
					break;
				}
			};

		return rv;
	}

	std::function<void(uint32_t streamID, uint8_t messageType, uint32_t timestamp, const uint8_t *payload, size_t len)> onmessage;
	Task onerror;
	Task onShutdownCompleteCallback;

protected:
	virtual std::shared_ptr<WriteReceipt> basicWrite(uint32_t streamID, uint8_t messageType, uint32_t timestamp, const uint8_t *payload, size_t len, Time startWithin, Time finishWithin) = 0;

	void callOnError()
	{
		onmessage = nullptr;
		Task cb;
		swap(cb, onerror);
		if(cb)
			cb();
	}

	void callOnShutdownComplete()
	{
		callOnError();
		Task cb;
		m_finished = true;
		swap(cb, onShutdownCompleteCallback);
		if(cb)
			cb();
	}

	bool isVideoSequenceSpecial(const uint8_t *payload, size_t len) const
	{
		if(isVideoCheckpointCommand(payload, len))
			return false;
		return Message::isVideoSequenceSpecial(payload, len);
	}

	bool isVideoCheckpointCommand(const uint8_t *payload, size_t len) const
	{
		if(len < 2)
			return false;
		if(TC_VIDEO_FRAMETYPE_COMMAND != (payload[0] & TC_VIDEO_FRAMETYPE_MASK))
			return false;
		if(Message::isVideoEnhanced(payload, len) or (TC_VIDEO_CODEC_AVC == Message::getVideoCodec(payload, len)))
		{
			if(len < 6)
				return false;
			return TC_VIDEO_COMMAND_RANDOM_ACCESS_CHECKPOINT == payload[5];
		}
		else
			return TC_VIDEO_COMMAND_RANDOM_ACCESS_CHECKPOINT == payload[1];
	}

	bool isAudioSequenceSpecial(const uint8_t *payload, size_t len) const
	{
		if(0 == len)
			return true;
		if(len < 2)
			return false;
		return (TC_AUDIO_CODEC_AAC == (payload[0] & TC_AUDIO_CODEC_MASK)) and (TC_AUDIO_AACPACKET_AUDIO_SPECIFIC_CONFIG == payload[1]);
	}

	struct StreamState {
		WriteReceiptChain m_chain;
		Bytes    m_lastKeyframe;
		uint32_t m_lastKeyframeTimestamp { 0 };

		uint32_t m_lastVideoTimestamp { 0 };
		uint32_t m_lastAudioTimestamp { 0 };
		uint32_t m_timestampShift { 0 };
	};

	std::map<uint32_t, StreamState> m_streamStates;
	bool m_open = { true };
	bool m_finished = { false };
	size_t m_videoMessages { 0 };
	size_t m_videoMessagesAbandoned { 0 };
	size_t m_videoMessagesLate { 0 };
	size_t m_audioMessages { 0 };
	size_t m_audioMessagesAbandoned { 0 };
	size_t m_audioMessagesLate { 0 };
};

class RTMPConnection : public Connection {
public:
	static std::shared_ptr<RTMPConnection> newRTMPConnection(bool isServer) {
		auto conn = share_ref(new RTMPConnection(isServer), false);

		conn->m_rtmp->onmessage = [conn] (uint32_t streamID, uint8_t messageType, uint32_t timestamp, const uint8_t *payload, size_t len) {
			if((TCMSG_USER_CONTROL == messageType) and (len >= 2) and (((TC_USERCONTROL_FLOW_SYNC >> 8) & 0xff) == payload[0]) and ((TC_USERCONTROL_FLOW_SYNC & 0xff) == payload[1]))
			{
				if(verbose)
					printf("ignoring TC_USERCONTROL_FLOW_SYNC from RTMP\n");
				return;
			}

			if(conn->onmessage)
				conn->onmessage(streamID, messageType, timestamp, payload, len);
		};

		conn->m_rtmp->onerror = [conn] { conn->callOnError(); };
		conn->m_adapter->onShutdownCompleteCallback = [conn] { conn->callOnShutdownComplete(); };

		return conn;
	}

	RTMPConnection(bool isServer) : m_connectionOpen(false)
	{
		m_adapter = share_ref(new PosixStreamPlatformAdapter(&mainRL), false);
		m_rtmp = share_ref(new RTMP(m_adapter), false);
		m_rtmp->init(isServer);
		m_rtmp->minOutstandingThresh = 16 * 1024; // default 64KB probably too big
		m_rtmp->maxAdditionalDelay = (delaycc_delay < INFINITY) ? delaycc_delay : 120.0;

		if(PROTO_RTMP_SIMPLE == (isServer ? inputProtocol : outputProtocol))
		{
			m_rtmp->setSimpleMode(true);
			m_rtmp->setChunkSize(1<<24); // maximum message size
			m_rtmp->minOutstandingThresh = m_rtmp->outstandingThresh = SIZE_MAX;
		}
	}

	bool setFd(int fd)
	{
		int tos = dscp << 2;
		setsockopt(fd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos));
		setsockopt(fd, IPPROTO_IPV6, IPV6_TCLASS, &tos, sizeof(tos));

		if(not m_adapter->setSocketFd(fd))
		{
			::close(fd);
			return false;
		}

		m_connectionOpen = true;
		return true;
	}

	void openConnection()
	{
		auto myself = share_ref(this);
		lookup([this, myself] (const std::vector<Address> &results) {
			if(m_open)
			{
				if(results.empty())
					goto error;

				auto addr = results.front();

				if(verbose) printf("connecting to %s\n", addr.toPresentation().c_str());

				int fd = socket(addr.getFamily(), SOCK_STREAM, IPPROTO_TCP);
				if(fd < 0)
				{
					::perror("socket");
					goto error;
				}
				{
					int flags = fcntl(fd, F_GETFL);
					flags |= O_NONBLOCK;
					fcntl(fd, F_SETFL, flags); // just so connect() won't block
				}
				if((connect(fd, addr.getSockaddr(), addr.getSockaddrLen()) < 0) and (EINPROGRESS != errno))
				{
					::perror("connect");
					::close(fd);
					goto error;
				}

				if(not setFd(fd))
					goto error;
			}

			return;
error:
			callOnError();
			(void) myself;
		});

		m_connectionOpen = true;
	}

	void close() override
	{
		Connection::close();
		m_rtmp->close();
	}

	void shutdown() override
	{
		retain();
		close();
		m_adapter->close();
		release();
	}

protected:
	std::shared_ptr<WriteReceipt> basicWrite(uint32_t streamID, uint8_t messageType, uint32_t timestamp, const uint8_t *payload, size_t len, Time startWithin, Time finishWithin) override
	{
		if(not m_connectionOpen)
			openConnection(); // lazy open outgoing connections so we know client is talking RTMP

		Priority pri = PRI_ROUTINE;
		switch(messageType)
		{
		case TCMSG_COMMAND:
		case TCMSG_COMMAND_EX:
			pri = PRI_IMMEDIATE;
			break;
		case TCMSG_AUDIO:
		case TCMSG_DATA:
		case TCMSG_DATA_EX:
			pri = interleave ? PRI_PRIORITY : PRI_IMMEDIATE;
			break;
		case TCMSG_VIDEO:
			pri = PRI_PRIORITY;
			break;
		}

		return m_rtmp->write(pri, streamID, messageType, timestamp, payload, len, startWithin, finishWithin);
	}

	std::shared_ptr<PosixStreamPlatformAdapter> m_adapter;
	std::shared_ptr<RTMP> m_rtmp;
	bool m_connectionOpen;
};

class RTMFPConnection : public Connection {
public:
	void close() override
	{
		Connection::close();
		if(m_controlSend)
			m_controlSend->close();
		if(m_controlRecv)
			m_controlRecv->close(); // needed for AIR compatibility; this is not good, clean close should be on all RecvFlows closing.
		m_netStreams.clear(); // closes all NetStream SendFlows
		checkFinishedLater();
	}

	void shutdown() override
	{
		auto recvFlows = m_recvFlows;
		for(auto it = recvFlows.begin(); it != recvFlows.end(); it++)
			(*it)->close();
		m_recvFlows.clear();
		close();
	}

	bool acceptControl(const std::shared_ptr<RecvFlow> &controlRecv)
	{
		assert(not m_controlRecv);

		uint32_t streamID = 0;
		if((not TCMetadata::parse(controlRecv->getMetadata(), &streamID, nullptr)) or (0 != streamID))
			return false;

		if(not m_controlSend)
		{
			m_controlSend = controlRecv->openReturnFlow(TCMetadata::encode(0, RO_SEQUENCE), PRI_IMMEDIATE);
			if(not m_controlSend)
				return false;

			wireControlSend();
		}

		controlRecv->onComplete = [this] (bool error) { callOnError(); };

		if(verbose)
			controlRecv->onFarAddressDidChange = [this, controlRecv] { printf("RTMFPConnection %p address changed %s\n", (void *)this, controlRecv->getFarAddress().toPresentation().c_str()); };

		controlRecv->accept();
		m_controlRecv = controlRecv;

		setOnMessage(controlRecv, 0, nullptr);

		controlRecv->setSessionCongestionDelay(delaycc_delay);
		controlRecv->setSessionTrafficClass(dscp << 2);

		return true;
	}

protected:
	struct NetStream {
		~NetStream()
		{
			if(m_video) m_video->close();
			if(m_audio) m_audio->close();
			if(m_data) m_data->close();
		}

		SendFlow * openFlowForType(const std::shared_ptr<RecvFlow> &control, uint32_t streamID, uint8_t messageType)
		{
			Priority pri = PRI_IMMEDIATE;
			ReceiveOrder rxIntent = RO_SEQUENCE;
			std::shared_ptr<SendFlow> *flowRef = &m_data;
			if(TCMSG_VIDEO == messageType)
			{
				flowRef = &m_video;
				if(not interleave)
					pri = PRI_PRIORITY; // lower than audio/data but still time-critical
				rxIntent = mediaReceiveIntent;
			}
			else if(TCMSG_AUDIO == messageType)
			{
				flowRef = &m_audio;
				rxIntent = mediaReceiveIntent;
			}

			if(not *flowRef)
			{
				*flowRef = control->openReturnFlow(TCMetadata::encode(streamID, rxIntent), pri);
				if(interleave)
					m_video = m_audio = m_data = *flowRef;
			}

			return flowRef->get();
		}

		std::shared_ptr<WriteReceipt> write(const std::shared_ptr<RecvFlow> &control, uint32_t streamID, uint8_t messageType, uint32_t timestamp, const uint8_t *payload, size_t len, Time startWithin, Time finishWithin)
		{
			if(not control)
				return nullptr; // connection must be open before we can write to NetStream flows

			auto flow = openFlowForType(control, streamID, messageType);
			if(not flow)
				return nullptr;

			return flow->write(TCMessage::message(messageType, timestamp, payload, len), startWithin, finishWithin);
		}

		std::shared_ptr<SendFlow> m_video;
		std::shared_ptr<SendFlow> m_audio;
		std::shared_ptr<SendFlow> m_data;
	};

	std::shared_ptr<WriteReceipt> basicWrite(uint32_t streamID, uint8_t messageType, uint32_t timestamp, const uint8_t *payload, size_t len, Time startWithin, Time finishWithin) override
	{
		if(0 == streamID)
			return m_controlSend->write(TCMessage::message(messageType, timestamp, payload, len), startWithin, finishWithin);

		auto &stream = m_netStreams[streamID];
		return stream.write(m_controlRecv, streamID, messageType, timestamp, payload, len, startWithin, finishWithin);
	}

	void wireControlSend()
	{
		m_controlSend->onException = [this] (uintmax_t reason) { callOnError(); };
		m_controlSend->onRecvFlow = [this] (std::shared_ptr<RecvFlow> flow) { acceptOther(flow); };
	}

	void deliverMessage(uint32_t streamID, const uint8_t *bytes, size_t len)
	{
		uint8_t messageType = 0;
		uint32_t timestamp = 0;
		size_t rv = TCMessage::parseHeader(bytes, bytes + len, &messageType, &timestamp);
		if(rv and onmessage)
			onmessage(streamID, messageType, timestamp, bytes + rv, len - rv);
	}

	bool shouldAlwaysDeliver(const uint8_t *bytes, size_t len)
	{
		uint8_t messageType = 0;
		size_t rv = TCMessage::parseHeader(bytes, bytes + len, &messageType, nullptr);
		if(not rv)
			return false;

		switch(messageType)
		{
		case TCMSG_VIDEO: return isVideoSequenceSpecial(bytes + rv, len - rv);
		case TCMSG_AUDIO: return isAudioSequenceSpecial(bytes + rv, len - rv);
		default: return true;
		}
	}

	void onLateMessage(const uint8_t *bytes, size_t len)
	{
		uint8_t messageType = 0;
		if(not TCMessage::parseHeader(bytes, bytes + len, &messageType, nullptr))
			return;

		switch(messageType)
		{
		case TCMSG_VIDEO: m_videoMessagesLate++; break;
		case TCMSG_AUDIO: m_audioMessagesLate++; break;
		default: break;
		}
	}

	void setOnMessage(const std::shared_ptr<RecvFlow> &flow, uint32_t streamID, const std::shared_ptr<ReorderBuffer> &reorderBuffer)
	{
		if(reorderBuffer)
		{
			reorderBuffer->onMessage = [this, streamID] (const uint8_t *bytes, size_t len, uintmax_t sequenceNumber, size_t fragmentCount, bool isLate) {
				if((not isLate) or shouldAlwaysDeliver(bytes, len))
					deliverMessage(streamID, bytes, len);
				else
					onLateMessage(bytes, len);
				if(isLate and (verbose > 1))
					printf("message %lu late, %s\n", (unsigned long)sequenceNumber, shouldAlwaysDeliver(bytes, len) ? "relayed anyway" : "dropped");
			};

			flow->onCumulativeAckDidMerge = [flow, reorderBuffer] {
				reorderBuffer->deliverThrough(flow->getCumulativeAckSequenceNumber());
			};
		}

		flow->onMessage = [this, streamID, flow, reorderBuffer] (const uint8_t *bytes, size_t len, uintmax_t sequenceNumber, size_t fragmentCount) {
			uint32_t syncID = 0;
			size_t count = 0;
			if(FlowSyncManager::parse(bytes, len, syncID, count))
			{
				m_syncManager.sync(syncID, count, flow);
				len = 0; // allow accounting for sequence numbers in reorderBuffer; deliverMessage will drop empty messages
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

	void acceptOther(const std::shared_ptr<RecvFlow> flow)
	{
		if(not m_controlRecv)
		{
			if(not acceptControl(flow))
				callOnError();
			return;
		}

		uint32_t streamID = 0;
		ReceiveOrder rxOrder = RO_SEQUENCE;

		if(not TCMetadata::parse(flow->getMetadata(), &streamID, &rxOrder))
			return;

		flow->setReceiveOrder(rxOrder);
		flow->setBufferCapacity((1<<24) - 1024); // 16MB, big enough for largest TCMessage

		std::shared_ptr<ReorderBuffer> reorderBuffer;
		if(RO_NETWORK == rxOrder)
			reorderBuffer = share_ref(new RunLoopReorderBuffer(&mainRL, reorderWindowPeriod), false);

		flow->onComplete = [this, flow, reorderBuffer] (bool error) {
			if(reorderBuffer)
				reorderBuffer->flush();
			m_recvFlows.erase(flow);
			checkFinishedLater();
		};

		setOnMessage(flow, streamID, reorderBuffer);

		flow->accept();
		m_recvFlows.insert(flow);
	}

	virtual void checkFinished()
	{
		if(m_recvFlows.empty() and (not m_open) and (not isFinished()))
			callOnShutdownComplete();
	}

	void checkFinishedLater()
	{
		auto myself = share_ref(this);
		mainRL.doLater([this, myself] { checkFinished(); });
	}

	FlowSyncManager m_syncManager;
	std::shared_ptr<SendFlow> m_controlSend;
	std::shared_ptr<RecvFlow> m_controlRecv;
	std::set<std::shared_ptr<RecvFlow>> m_recvFlows;
	std::map<uint32_t, NetStream> m_netStreams;
};

class RTMFPOutgoingConnection : public RTMFPConnection {
public:
	RTMFPOutgoingConnection() : m_platform(&mainRL, &mainPerformer, &workerPerformer)
	{
		m_platform.onShutdownCompleteCallback = [this] { m_rtmfpShutdownComplete = true; checkFinishedLater(); };

		m_crypto.init(false, nullptr);
		m_crypto.setHMACSendAlways(requireHMAC);
		m_crypto.setHMACRecvRequired(requireHMAC);
		m_crypto.setSSeqSendAlways(requireSSEQ);
		m_crypto.setSSeqRecvRequired(requireSSEQ);

		m_rtmfp = share_ref(new RTMFP(&m_platform, &m_crypto), false);
		m_platform.setRtmfp(m_rtmfp.get());

		m_rtmfp->setDefaultSessionKeepalivePeriod(10);
		m_rtmfp->setDefaultSessionRetransmitLimit(20);
		m_rtmfp->setDefaultSessionIdleLimit(120);
	}

	void shutdown() override
	{
		RTMFPConnection::shutdown();
		m_rtmfp->shutdown(true);
	}

protected:
	void checkFinished() override
	{
		if(m_recvFlows.empty() and not m_open)
			m_rtmfp->shutdown(false);

		if(m_rtmfpShutdownComplete)
			RTMFPConnection::checkFinished();
	}

	std::string findConnectUri(uint32_t streamID, uint8_t messageType, const uint8_t *payload, size_t len)
	{
		if(overrideRtmfpUri)
			return overrideRtmfpUri;

		if(len and (0 == streamID) and ((TCMSG_COMMAND == messageType) or (TCMSG_COMMAND_EX == messageType)))
		{
			const uint8_t *cursor = payload;
			const uint8_t *limit = cursor + len;

			if((TCMSG_COMMAND_EX == messageType) and (0 != *cursor++)) // COMMAND_EX has a format id, and only format id=0 is defined
				goto notfound;

			std::vector<std::shared_ptr<AMF0>> args;
			if( (not AMF0::decode(cursor, limit, args))
			 or (args.size() < 3)
			 or (not args[0]->isString())
			 or (not args[2]->isObject())
			 or (0 != strcmp(args[0]->stringValue(), "connect"))
			)
				goto notfound;

			auto tcUrl = args[2]->getValueAtKey("tcUrl");
			if(tcUrl and tcUrl->isString())
				return tcUrl->stringValue();
		}

notfound:
		return backupRtmfpUri;
	}

	void openConnection(const std::string &uri)
	{
		m_controlSend = m_rtmfp->openFlow(m_crypto.makeEPD(nullptr, uri.c_str(), nullptr), TCMetadata::encode(0, RO_SEQUENCE), PRI_IMMEDIATE);
		wireControlSend();

		m_platform.addUdpInterface(0, AF_INET);
		m_platform.addUdpInterface(0, AF_INET6);

		auto myself = share_ref(this);
		lookup([this, myself] (const std::vector<Address> &results) {
			if(m_open)
			{
				for(auto it = results.begin(); it != results.end(); it++)
					m_controlSend->addCandidateAddress(*it);
			}
		});
	}

	std::shared_ptr<WriteReceipt> basicWrite(uint32_t streamID, uint8_t messageType, uint32_t timestamp, const uint8_t *payload, size_t len, Time startWithin, Time finishWithin) override
	{
		if(not m_controlSend)
			openConnection(findConnectUri(streamID, messageType, payload, len));

		return RTMFPConnection::basicWrite(streamID, messageType, timestamp, payload, len, startWithin, finishWithin);
	}

	FlashCryptoAdapter_OpenSSL m_crypto;
	PerformerPosixPlatformAdapter m_platform;
	std::shared_ptr<RTMFP> m_rtmfp;
	bool m_rtmfpShutdownComplete { false };
};

class RTWebSocketConnection : public Connection {
public:
	RTWebSocketConnection()
	{}

	bool setFd(int fd)
	{
		 if(m_platformStream)
			return false;
		m_platformStream = share_ref(new PosixStreamPlatformAdapter(&mainRL), false);
		m_wsMessageAdapter = share_ref(new rtws::SimpleWebSocketMessagePlatformAdapter(m_platformStream), false);

		int tos = dscp << 2;
		setsockopt(fd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos));
		setsockopt(fd, IPPROTO_IPV6, IPV6_TCLASS, &tos, sizeof(tos));

		if(not m_platformStream->setSocketFd(fd))
		{
			::close(fd);
			return false;
		}

		auto myself = share_ref(this);

		m_platformStream->onShutdownCompleteCallback = [this, myself] { callOnShutdownComplete(); };

		m_websock = share_ref(new SimpleWebSocket_OpenSSL(m_platformStream), false);
		m_wsMessageAdapter->init(m_websock);
		m_rtws = share_ref(new rtws::RTWebSocket(m_wsMessageAdapter), false);

		m_wsMessageAdapter->onOpen = [this, myself] {
			if(verbose) printf("RTWebSocketConnection %p WebSocket message adapter: onOpen\n", (void *)this);
			m_rtws->init();
		};
		m_rtws->onRecvFlow = [this] (std::shared_ptr<rtws::RecvFlow> flow) { acceptControl(flow); };
		m_rtws->onError = [this, myself] { callOnError(); };
		m_rtws->minOutstandingThresh = 1024 * 16; // default 64KB probably too big
		m_rtws->maxAdditionalDelay = (delaycc_delay < INFINITY) ? delaycc_delay : 120.0;

		return true;
	}

	void acceptControl(std::shared_ptr<rtws::RecvFlow> flow)
	{
		uint32_t streamID = 0;
		if(m_controlRecv or (not TCMetadata::parse(flow->getMetadata(), &streamID, nullptr)) or (0 != streamID))
			return;

		m_controlRecv = flow;
		flow->onComplete = [this] { callOnError(); };
		flow->accept();
		setOnMessage(flow, streamID);

		m_controlSend = flow->openReturnFlow(TCMetadata::encode(0, RO_SEQUENCE), PRI_IMMEDIATE);
		m_controlSend->onException = [this] (uintmax_t reason, const std::string &description) { callOnError(); };
		m_controlSend->onRecvFlow = [this] (std::shared_ptr<rtws::RecvFlow> flow) { acceptOther(flow); };

		if(verbose) printf("RTWebSocketConnection %p accept control flow\n", (void *)this);
	}

	void close() override
	{
		Connection::close();
		if(m_controlSend)
			m_controlSend->close();
		m_netStreams.clear();
		if(m_rtws)
			m_rtws->close();
		if(m_platformStream)
			m_platformStream->close();
	}

	void shutdown() override
	{
		close();
	}

protected:
	struct NetStream {
		~NetStream()
		{
			if(m_video) m_video->close();
			if(m_audio) m_audio->close();
			if(m_data) m_data->close();
		}

		rtws::SendFlow * openFlowForType(const std::shared_ptr<rtws::RecvFlow> &control, uint32_t streamID, uint8_t messageType)
		{
			Priority pri = PRI_IMMEDIATE;
			std::shared_ptr<rtws::SendFlow> *flowRef = &m_data;
			if(TCMSG_VIDEO == messageType)
			{
				flowRef = &m_video;
				if(not interleave)
					pri = PRI_PRIORITY;
			}
			else if(TCMSG_AUDIO == messageType)
				flowRef = &m_audio;

			if(not *flowRef)
			{
				*flowRef = control->openReturnFlow(TCMetadata::encode(streamID, RO_SEQUENCE), pri);
				if(interleave)
					m_video = m_audio = m_data = *flowRef;
			}

			return flowRef->get();
		}

		std::shared_ptr<WriteReceipt> write(const std::shared_ptr<rtws::RecvFlow> &control, uint32_t streamID, uint8_t messageType, uint32_t timestamp, const uint8_t *payload, size_t len, Time startWithin, Time finishWithin)
		{
			auto flow = openFlowForType(control, streamID, messageType);
			if(not flow)
				return nullptr;

			return flow->write(TCMessage::message(messageType, timestamp, payload, len), startWithin, finishWithin);
		}

		std::shared_ptr<rtws::SendFlow> m_video;
		std::shared_ptr<rtws::SendFlow> m_audio;
		std::shared_ptr<rtws::SendFlow> m_data;
	};

	std::shared_ptr<WriteReceipt> basicWrite(uint32_t streamID, uint8_t messageType, uint32_t timestamp, const uint8_t *payload, size_t len, Time startWithin, Time finishWithin) override
	{
		if(0 == streamID)
			return m_controlSend->write(TCMessage::message(messageType, timestamp, payload, len), startWithin, finishWithin);

		auto &stream = m_netStreams[streamID];
		return stream.write(m_controlRecv, streamID, messageType, timestamp, payload, len, startWithin, finishWithin);
	}

	void setOnMessage(std::shared_ptr<rtws::RecvFlow> flow, uint32_t streamID)
	{
		flow->onMessage = [this, streamID] (const uint8_t *bytes, size_t len, uintmax_t messageNumber) {
			uint32_t syncID = 0;
			size_t count = 0;
			if(FlowSyncManager::parse(bytes, len, syncID, count))
				return; // TODO make a FlowSyncManager for RTWS. don't relay flow sync messages.

			uint8_t messageType = 0;
			uint32_t timestamp = 0;
			size_t rv = TCMessage::parseHeader(bytes, bytes + len, &messageType, &timestamp);
			if(rv and onmessage)
				onmessage(streamID, messageType, timestamp, bytes + rv, len - rv);
		};
	}

	void acceptOther(std::shared_ptr<rtws::RecvFlow> flow)
	{
		if(not m_open)
			return;

		uint32_t streamID = 0;
		if(not TCMetadata::parse(flow->getMetadata(), &streamID, nullptr))
			return;
		flow->setBufferCapacity((1<<24) - 1);
		flow->onComplete = [this, flow] {
			m_recvFlows.erase(flow);
		};

		setOnMessage(flow, streamID);

		flow->accept();
		m_recvFlows.insert(flow);
	}

	std::shared_ptr<rtws::SendFlow> m_controlSend;
	std::shared_ptr<rtws::RecvFlow> m_controlRecv;
	std::set<std::shared_ptr<rtws::RecvFlow>> m_recvFlows;
	std::map<uint32_t, NetStream> m_netStreams;

	std::shared_ptr<rtws::RTWebSocket> m_rtws;
	std::shared_ptr<SimpleWebSocket> m_websock;
	std::shared_ptr<rtws::SimpleWebSocketMessagePlatformAdapter> m_wsMessageAdapter;
	std::shared_ptr<PosixStreamPlatformAdapter> m_platformStream;
};

class Client : public Object {
public:
	~Client()
	{
		if(verbose > 1) printf("~Client %p\n", (void *)this);
	}

	static void newRTMPClient(int fd)
	{
		auto rv = RTMPConnection::newRTMPConnection(true);
		if(not rv->setFd(fd))
			return;

		newClient(rv);
	}

	static void newRTWSClient(int fd)
	{
		auto rv = share_ref(new RTWebSocketConnection(), false);
		if(not rv->setFd(fd))
			return;

		newClient(rv);
	}

	static void newRTMFPClient(std::shared_ptr<RecvFlow> flow)
	{
		auto rv = share_ref(new RTMFPConnection(), false);
		if(not rv->acceptControl(flow))
			return;
		if(verbose) printf("RTMFPConnection %p accepted from %s\n", (void *)rv.get(), flow->getFarAddress().toPresentation().c_str());

		newClient(rv);
	}

	void close()
	{
		if(verbose) printf("closing Client %p\n", (void *)this);

		retain();
		m_incoming->onerror = m_outgoing->onerror = nullptr;
		m_incoming->close();
		m_outgoing->close();
		release();
	}

	void shutdown()
	{
		retain();
		m_incoming->shutdown();
		m_outgoing->shutdown();
		release();
	}

protected:
	static void newClient(const std::shared_ptr<Connection> &incoming)
	{
		auto client = share_ref(new Client(), false);
		if(verbose) printf("new Client %p\n", (void *)client.get());

		client->m_incoming = incoming;
		client->makeOutgoing();
		client->wireConnections();

		clients.insert(client);
	}

	void makeOutgoing()
	{
		if(PROTO_RTMFP == outputProtocol)
			m_outgoing = share_ref(new RTMFPOutgoingConnection(), false);
		else // PROTO_RTMP or PROTO_RTMP_SIMPLE
			m_outgoing = RTMPConnection::newRTMPConnection(false);
	}

	void printMessage(const char *direction, uint32_t streamID, uint8_t messageType, uint32_t timestamp, const uint8_t *payload, size_t len)
	{
		if(verbose > 1)
		{
			printf("%s onmessage streamID:%u, messageType:%u, ts:%u, len:%lu\n", direction, streamID, messageType, timestamp, (unsigned long)len);

			if(0 == len)
				return;

			const char *messageTypeDesc = nullptr;
			switch(messageType)
			{
			case TCMSG_COMMAND: messageTypeDesc = "TCMSG_COMMAND"; break;
			case TCMSG_COMMAND_EX: messageTypeDesc = "TCMSG_COMMAND_EX"; break;
			case TCMSG_DATA: messageTypeDesc = "TCMSG_DATA"; break;
			case TCMSG_DATA_EX: messageTypeDesc = "TCMSG_DATA_EX"; break;

			case TCMSG_USER_CONTROL:
				Hex::print("TCMSG_USER_CONTROL", payload, len);
				return;

			default: return;
			}

			const uint8_t *cursor = payload;
			const uint8_t *limit = cursor + len;

			if(((TCMSG_COMMAND_EX == messageType) or (TCMSG_DATA_EX == messageType)) and (0 != *cursor++)) // _EX has a format id and only format 0 is defined
				return;

			std::vector<std::shared_ptr<AMF0>> args;
			AMF0::decode(cursor, limit, args);
			printf("%s %s\n", direction, messageTypeDesc);
			for(auto it = args.begin(); it != args.end(); it++)
				printf("  %s\n", (*it)->repr().c_str());
		}
	}

	void wireConnections()
	{
		m_incoming->onmessage = [this] (uint32_t streamID, uint8_t messageType, uint32_t timestamp, const uint8_t *payload, size_t len) {
			printMessage("upstream", streamID, messageType, timestamp, payload, len);
			m_outgoing->write(streamID, messageType, timestamp, payload, len);
		};

		m_outgoing->onmessage = [this] (uint32_t streamID, uint8_t messageType, uint32_t timestamp, const uint8_t *payload, size_t len) {
			printMessage("downstream", streamID, messageType, timestamp, payload, len);
			m_incoming->write(streamID, messageType, timestamp, payload, len);
		};

		m_incoming->onerror = m_outgoing->onerror = [this] { close(); };

		m_incoming->onShutdownCompleteCallback = m_outgoing->onShutdownCompleteCallback = [this] {
			if(m_incoming->isFinished() and m_outgoing->isFinished())
			{
				if(verbose) printf("erasing client %p\n", (void *)this);
				clients.erase(share_ref(this));
			}
		};
	}

	std::shared_ptr<Connection> m_incoming;
	std::shared_ptr<Connection> m_outgoing;
};

void signal_handler(int param)
{
	interrupted = true;
}

Protocol protoFromName(const char *name)
{
	if(0 == strcmp("rtmp", name))
		return PROTO_RTMP;
	if(0 == strcmp("rtmp-simple", name))
		return PROTO_RTMP_SIMPLE;
	if(0 == strcmp("rtws", name))
		return PROTO_RTWS;
	if(0 == strcmp("rtmfp", name))
		return PROTO_RTMFP;
	return PROTO_UNSPEC;
}

bool addInterface(PosixPlatformAdapter *platform, int port, int family)
{
	const char *familyName = (AF_INET6 == family) ? "IPv6" : "IPv4";
	auto addr = platform->addUdpInterface(port, family);
	if(addr)
		printf("bound to %s port %d\n", familyName, addr->getPort());
	else
		printf("error: couldn't bind to %s port %d\n", familyName, port);
	return !!addr;
}

bool listenTCP(const Address &addr)
{
	int fd = socket(addr.getFamily(), SOCK_STREAM, IPPROTO_TCP);
	if(fd < 0)
	{
		::perror("socket");
		return false;
	}
	{
		int val = 1;
		if(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val)))
			::perror("SO_REUSEADDR");

		// (for IPv6 sockets) set IPV6_V6ONLY for cross-platform consistency.
		// the safe and portable thing is to always have separate sockets for each family.
		setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &val, sizeof(val));
	}
	if(bind(fd, addr.getSockaddr(), addr.getSockaddrLen()))
	{
		::perror("bind");
		return false;
	}
	if(listen(fd, 5))
	{
		::perror("listen");
		return false;
	}

	mainRL.registerDescriptor(fd, RunLoop::READABLE, [] (RunLoop *sender, int fd, RunLoop::Condition cond) {
		Address::in_sockaddr boundAddr;
		socklen_t addrLen = sizeof(boundAddr);
		int newFd = accept(fd, &boundAddr.s, &addrLen);
		if(newFd < 0)
		{
			::perror("accept");
			return;
		}

		if(PROTO_RTWS == inputProtocol)
		{
			if(verbose) printf("accepted RTWS from %s\n", Address(&boundAddr.s).toPresentation().c_str());
			Client::newRTWSClient(newFd);
		}
		else
		{
			if(verbose) printf("accepted RTMP from %s\n", Address(&boundAddr.s).toPresentation().c_str());
			Client::newRTMPClient(newFd);
		}
	});

	return true;
}

bool listenTCP(int port, int family)
{
	Address addr;
	if(not addr.setFamily(family))
		return false;
	addr.setPort(port);
	return listenTCP(addr);
}

bool appendAddress(const char *presentationForm, std::vector<Address> &dst)
{
	Address addr;
	if(not addr.setFromPresentation(presentationForm))
		return false;
	dst.push_back(addr);
	return true;
}

// https://www.iana.org/assignments/dscp-registry/dscp-registry.xhtml
std::map<std::string, int> dscp_codepoints({
	{ "CS0", 0 }, { "CS1", 8 }, { "CS2", 16 }, { "CS3", 24 }, { "CS4", 32 }, { "CS5", 40 }, { "CS6", 48 }, { "CS7", 56 },
	{ "AF11", 10 }, { "AF12", 12 }, { "AF13", 14 },
	{ "AF21", 18 }, { "AF22", 20 }, { "AF23", 22 },
	{ "AF31", 26 }, { "AF32", 28 }, { "AF33", 30 },
	{ "AF41", 34 }, { "AF42", 36 }, { "AF43", 38 },
	{ "EF", 46 }, { "VOICE-ADMIT", 44 },
	{ "LE", 1 }
});
int convert_dscp(const std::string &name)
{
	errno = 0;
	if(dscp_codepoints.count(name))
		return dscp_codepoints[name];
	const char *s = name.c_str();
	char *endptr = nullptr;
	int rv = int(strtol(s, &endptr, 0));
	if((0 == rv) and (endptr == s)) // no conversion, not all strtol() set errno
		errno = EINVAL;
	return rv;
}

int usage(const char *prog, int rv, const char *msg = nullptr, const char *arg = nullptr)
{
	if(msg)
		printf("%s", msg);
	if(arg)
		printf("%s", arg);
	if(msg or arg)
		printf("\n");

	printf("usage: %s -i proto -o proto (-4|-6|-B) [options] dest-host [dest-port]\n", prog);
	printf("  -i proto      -- listen for proto (rtmp|rtmp-simple|rtws|rtmfp)\n");
	printf("  -o proto      -- relay to proto (rtmp|rtmp-simple|rtmfp)\n");
	printf("  -I            -- interleave A/V on same flow/priority\n");
	printf("  -V sec        -- video queue lifetime (default %.3Lf)\n", videoLifetime);
	printf("  -A sec        -- audio queue lifetime (default %.3Lf)\n", audioLifetime);
	printf("  -F sec        -- finish-by margin (default %.3Lf)\n", finishByMargin);
	printf("  -e secs       -- expire previous GOP start-by margin (default %.3Lf)\n", previousGopStartByMargin);
	printf("  -R            -- request ASAP receive on A/V (rtmfp send)\n");
	printf("  -r sec        -- reorder window duration (rtmfp receive, default %.3Lf)\n", reorderWindowPeriod);
	printf("  -G            -- (experimental) collapse audio gaps in the timeline (only use with 48kHz AAC)\n");
	printf("  -E            -- don't expire previous GOP\n");
	printf("  -c            -- send checkpoint after keyframe\n");
	printf("  -C sec        -- checkpoint queue lifetime (default %.3Lf)\n", checkpointLifetime);
	printf("  -M            -- don't replay previous keyframe if missing at checkpoint receive\n");
	printf("  -T DSCP|name  -- set DiffServ field on outgoing packets (default %d)\n", dscp);
	printf("  -X sec        -- set congestion extra delay threshold (rtmfp, rtws, rtmp, default %.3Lf)\n", delaycc_delay);
	printf("  -H            -- don't require HMAC (rtmfp)\n");
	printf("  -S            -- don't require session sequence numbers (rtmfp)\n");
	printf("  -p port       -- port for -4/-6 (default %d)\n", port);
	printf("  -4            -- bind to IPv4 0.0.0.0:%d\n", port);
	printf("  -6            -- bind to IPv6 [::]:%d\n", port);
	printf("  -B addr:port  -- bind to addr:port explicitly\n");
	printf("  -u uri        -- override URI for IHello (rtmfp, default tcUrl from connect command)\n");
	printf("  -L redir-spec -- add redirector/LB spec <name>@<ip:port>[,ip:port...]\n");
	printf("  -l user:passw -- add redirector username:password\n");
	printf("  -d addr:port  -- advertise addr:port at redirector\n");
	printf("  -D            -- suppress redirector advertising reflexive (derived) address\n");
	printf("  -v            -- increase verbose output\n");
	printf("  -h            -- show this help\n");
	return rv;
}

}

int main(int argc, char **argv)
{
	bool ipv4 = false;
	bool ipv6 = false;
	std::vector<Address> bindAddrs;
	int ch;
	bool advertiseReflexive = true;
	std::map<std::string, std::string> redirectAuth;
	std::map<std::string, std::vector<Address>> redirectorSpecs;
	std::vector<Address> advertiseAddresses;
	std::vector<std::shared_ptr<RedirectorClient>> redirectors;

	while((ch = getopt(argc, argv, "i:o:IV:A:F:e:Rr:GEcC:MT:X:HSp:46B:u:L:l:d:Dvh")) != -1)
	{
		switch(ch)
		{
		case 'i':
			if(PROTO_UNSPEC == (inputProtocol = protoFromName(optarg)))
				return usage(argv[0], 1, "unrecognized input protocol: ", optarg);
			break;
		case 'o':
			if(PROTO_UNSPEC == (outputProtocol = protoFromName(optarg)))
				return usage(argv[0], 1, "unrecognized output protocol: ", optarg);
			if(PROTO_RTWS == outputProtocol)
				return usage(argv[0], 1, "rtws not supported for -o");
			break;
		case 'I':
			interleave = true;
			break;
		case 'V':
			videoLifetime = atof(optarg);
			break;
		case 'A':
			audioLifetime = atof(optarg);
			break;
		case 'F':
			finishByMargin = atof(optarg);
			break;
		case 'e':
			previousGopStartByMargin = atof(optarg);
			break;
		case 'R':
			mediaReceiveIntent = RO_NETWORK;
			break;
		case 'r':
			reorderWindowPeriod = atof(optarg);
			break;
		case 'G':
			collapseAudioGaps = true;
			break;
		case 'E':
			expirePreviousGop = false;
			break;
		case 'c':
			sendVideoCheckpoint = true;
			break;
		case 'C':
			checkpointLifetime = atof(optarg);
			break;
		case 'M':
			replayCheckpointFrame = false;
			break;
		case 'T':
			dscp = convert_dscp(optarg);
			if(errno)
			{
				printf("DiffServ names: ");
				for(auto it = dscp_codepoints.begin(); it != dscp_codepoints.end(); it++)
					printf("%s ", it->first.c_str());
				printf("\n");
				return usage(argv[0], 1, "unrecognized DiffServ name: ", optarg);
			}
			break;
		case 'X':
			delaycc_delay = atof(optarg);
			break;
		case 'H':
			requireHMAC = false;
			break;
		case 'S':
			requireSSEQ = false;
			break;
		case '4':
			ipv4 = true;
			break;
		case '6':
			ipv6 = true;
			break;
		case 'B':
			if(not appendAddress(optarg, bindAddrs))
				return usage(argv[0], 1, "can't parse bind address: ", optarg);
			break;
		case 'p':
			port = atoi(optarg);
			break;
		case 'u':
			overrideRtmfpUri = optarg;
			break;
		case 'L':
			if(not parse_redirector_spec(optarg, redirectorSpecs))
				return usage(argv[0], 1, "unrecognized redirector spec: ", optarg);
			break;
		case 'l':
			{
				std::string str = optarg;
				memset(optarg, '#', strlen(optarg));
				auto pos = str.find(":");
				if(std::string::npos == pos)
					return usage(argv[0], 1, "unrecognized redirector username:password");
				redirectAuth[str.substr(0, pos)] = str.substr(pos + 1);
			}
			break;
		case 'd':
			if(not appendAddress(optarg, advertiseAddresses))
				return usage(argv[0], 1, "can't parse address to advertise at redirector: ", optarg);
			break;
		case 'D':
			advertiseReflexive = false;
			break;
		case 'v':
			verbose++;
			break;

		case 'h':
		default:
			return usage(argv[0], 'h' != ch);
		}
	}

	if(argc <= optind)
		return usage(argv[0], 1, "specify destination hostname");
	desthostname = argv[optind];
	if(argc > optind + 1)
		destservname = argv[optind + 1];

	if(PROTO_UNSPEC == inputProtocol)
		return usage(argv[0], 1, "specify input protocol");
	if(PROTO_UNSPEC == outputProtocol)
		return usage(argv[0], 1, "specify output protocol");
	if(not (bindAddrs.size() or ipv4 or ipv6))
		return usage(argv[0], 1, "specify at least -4, -6, or -B");

	FlashCryptoAdapter_OpenSSL crypto;
	if(not crypto.init(true, nullptr))
	{
		printf("crypto.init error\n");
		return 1;
	}
	crypto.setHMACSendAlways(requireHMAC);
	crypto.setHMACRecvRequired(requireHMAC);
	crypto.setSSeqSendAlways(requireSSEQ);
	crypto.setSSeqRecvRequired(requireSSEQ);

	PerformerPosixPlatformAdapter platform(&mainRL, &mainPerformer, &workerPerformer);

	bool rtmfpShutdownComplete = false;
	platform.onShutdownCompleteCallback = [&rtmfpShutdownComplete] { rtmfpShutdownComplete = true; };

	RTMFP rtmfp(&platform, &crypto);
	platform.setRtmfp(&rtmfp);

	rtmfp.setDefaultSessionKeepalivePeriod(10);
	rtmfp.setDefaultSessionRetransmitLimit(20);
	rtmfp.setDefaultSessionIdleLimit(120);

	if(PROTO_RTMFP == inputProtocol)
	{
		for(auto it = bindAddrs.begin(); it != bindAddrs.end(); it++)
		{
			auto boundAddr = platform.addUdpInterface(it->getSockaddr());
			if(not boundAddr)
			{
				printf("can't bind to requested address: %s\n", it->toPresentation().c_str());
				return 1;
			}
			printf("bound to %s\n", boundAddr->toPresentation().c_str());
		}

		// do IPv4 first in case IPv6 binds to both families
		if(ipv4 and not addInterface(&platform, port, AF_INET))
			return 1;

		if(ipv6 and not addInterface(&platform, port, AF_INET6))
			return 1;

		rtmfp.onRecvFlow = Client::newRTMFPClient;

		for(auto it = redirectorSpecs.begin(); it != redirectorSpecs.end(); it++)
		{
			auto hostname = it->first;
			Bytes epd = crypto.makeEPD(nullptr, nullptr, hostname.c_str());
			auto redirectorClient = share_ref(new FlashCryptoRunLoopRedirectorClient(&rtmfp, epd, &mainRL, &crypto), false);
			redirectors.push_back(redirectorClient);
			auto redirectorClient_ptr = redirectorClient.get();
			config_redirector_client(redirectorClient_ptr, redirectAuth, it->second, advertiseAddresses, advertiseReflexive);

			if(verbose)
			{
				redirectorClient->onReflexiveAddress = [hostname, redirectorClient_ptr] (const Address &addr) {
					printf("redirector %s@%s reports reflexive address %s\n", hostname.c_str(), redirectorClient_ptr->getRedirectorAddress().toPresentation().c_str(), addr.toPresentation().c_str());
				};
				redirectorClient->onStatus = [hostname, redirectorClient_ptr] (RedirectorClient::Status status) {
					printf("redirector %s@%s status %d\n", hostname.c_str(), redirectorClient_ptr->getRedirectorAddress().toPresentation().c_str(), status);
				};
			}

			redirectorClient->connect();
		}
	}
	else
	{
		if(not redirectorSpecs.empty())
			printf("Warning: redirectors are only available with RTMFP input. Ignorning redirector specifications.\n");

		for(auto it = bindAddrs.begin(); it != bindAddrs.end(); it++)
			if(not listenTCP(*it))
				return 1;
		if(ipv4 and not listenTCP(port, AF_INET))
			return 1;
		if(ipv6 and not listenTCP(port, AF_INET6))
			return 1;
	}

	::signal(SIGINT, signal_handler);
	::signal(SIGTERM, signal_handler);

	mainRL.onEveryCycle = [&rtmfp, &rtmfpShutdownComplete] {
		if(interrupted)
		{
			interrupted = false;
			printf("interrupted. %s\n", stopping ? "quitting" : "shutting down...");
			if(stopping)
			{
				// failsafe
				clients.clear();
				rtmfpShutdownComplete = true;
			}
			stopping = true;

			auto safeClients = clients;
			for(auto it = safeClients.begin(); it != safeClients.end(); it++)
				(*it)->shutdown();

			rtmfp.shutdown(true);
		}

		if(stopping and clients.empty() and rtmfpShutdownComplete)
			mainRL.stop();
	};

	auto workerThread = std::thread([] { workerRL.run(); });
	auto lookupThread = std::thread([] { lookupRL.run(); });

	mainRL.run();

	workerPerformer.perform([] { workerRL.stop(); });
	lookupPerformer.perform([] { lookupRL.stop(); });

	workerThread.join();
	lookupThread.join();

	mainPerformer.close();
	workerPerformer.close();
	lookupPerformer.close();

	printf("end.\n");

	return 0;
}
