// Copyright © 2022 Michael Thornburgh
// SPDX-License-Identifier: MIT

// TC Server, a simple live media server for RTMFP/RTMP “Tin-Can” clients.
// See the help message and tcserver.md for more information.

// TODO: rate limits
// TODO: support http://zenomt.com/ns/rtmfp#media (rtmfp, rtws)

#include <cassert>
#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

extern "C" {
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <math.h>
#include <netinet/tcp.h>
#include <time.h>
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
#include "rtmfp/URIParse.hpp"

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

using Args = std::vector<std::shared_ptr<AMF0>>;
using LogAttributes = std::vector<std::pair<const char *, std::shared_ptr<AMF0>>>;

namespace {

enum Protocol { PROTO_UNSPEC, PROTO_RTMP, PROTO_RTMP_SIMPLE, PROTO_RTWS, PROTO_RTMFP };

enum {
	TC_VIDEO_COMMAND_RANDOM_ACCESS_CHECKPOINT = 3
};

int verbose = 0;
bool requireHMAC = true;
bool requireSSEQ = true;
Time videoLifetime = 2.0;
Time audioLifetime = 2.2;
Time finishByMargin = 0.1;
Time previousGopStartByMargin = 0.1;
Time checkpointLifetime = 4.5;
Time reorderWindowPeriod = 1.0;
Time delaycc_delay = INFINITY;
Time shutdownTimeout = 300.0;
Time gracefulShutdownTimeout = 300.0;
bool expirePreviousGop = true;
bool allowMultipleConnections = false;
bool interrupted = false;
bool stopping = false;
bool showStats = false;
bool unregister = false;
bool shuttingDown = false;
bool allowConnectDuringShutdown = false;
int dscp = 0;
size_t maxNetStreamsPerClient = 1024; // arbitrary
uint32_t timestampAdjustmentMargin = 4000;
std::vector<Bytes> secrets;
const char *serverInfo = nullptr;
std::vector<std::shared_ptr<RedirectorClient>> redirectors;
pid_t pid;
std::string serverId;
Time streamAccountingMin = 1.0;
Time streamAccountingMax = 2.0;

PreferredRunLoop mainRL;
Performer mainPerformer(&mainRL);
PreferredRunLoop workerRL;
Performer workerPerformer(&workerRL);
FlashCryptoAdapter *flashcrypto = nullptr; // set in main()

class Client;
std::map<Bytes, std::shared_ptr<Client>> clients;

size_t currentPublishCount = 0;
size_t currentSubscribeCount = 0;
size_t rtmfpAcceptCount = 0;
size_t rtmpAcceptCount = 0;
size_t rtwsAcceptCount = 0;
size_t connectCount = 0;
size_t publishCount = 0;
size_t subscribeCount = 0;
size_t broadcastCount = 0;
size_t relaysIn = 0;
size_t relaysOut = 0;
size_t lookupCount = 0;
size_t introCount = 0;
Time   publishedDuration = 0.0;
Time   playedDuration = 0.0;

std::string protocolDescription(Protocol protocol)
{
	switch(protocol)
	{
	case PROTO_RTMP: return "rtmp";
	case PROTO_RTMP_SIMPLE: return "rtmp-simple";
	case PROTO_RTWS: return "rtws";
	case PROTO_RTMFP: return "rtmfp";
	default: return "unspecified";
	}
}

std::string redirectorStatusDescription(RedirectorClient::Status status)
{
	switch(status)
	{
	case RedirectorClient::STATUS_IDLE:                  return "idle";
	case RedirectorClient::STATUS_CONNECTING:            return "connecting";
	case RedirectorClient::STATUS_CONNECTED:             return "connected";
	case RedirectorClient::STATUS_DISCONNECTED:          return "disconnected";
	case RedirectorClient::STATUS_DISCONNECTED_BAD_AUTH: return "disconnected-bad-auth";
	case RedirectorClient::STATUS_CLOSED:                return "closed";
	default: return "unknown-status";
	}
}

std::string hexHMACSHA256(const Bytes &key, const std::string &app)
{
	uint8_t md[32] = { 0 };
	flashcrypto->hmacSHA256(md, key.data(), key.size(), app.data(), app.size());
	return Hex::encode(md, sizeof(md));
}

std::map<std::string, std::string> splitParams(const std::string &str, const std::string &seps)
{
	std::map<std::string, std::string> rv;

	auto params = URIParse::split(str, seps);
	for(auto it = params.begin(); it != params.end(); it++)
	{
		auto parts = URIParse::split(*it, "=", 2);
		rv[parts[0]] = parts.size() > 1 ? parts[1] : "";
	}

	return rv;
}

long double paramValueToFloat(const std::string &str, long double defaultValue)
{
	if(str.empty())
		return defaultValue;

	const char *valueStr = str.c_str();
	char *endptr = nullptr;
	long double rv = strtold(valueStr, &endptr);
	return ((endptr == valueStr) or std::isnan(rv)) ? defaultValue : rv;
}

Time unixCurrentTime()
{
	// note: C++20 guarantees that std::chrono::system_clock measures
	// Unix time, but we're C++11 right now, which doesn't.

	struct timespec tp;
	if(::clock_gettime(CLOCK_REALTIME, &tp))
		return -1.0;
	return Time(tp.tv_sec) + Time(tp.tv_nsec) / Time(1000000000.0);
}

void jsonLog(const std::string &type, const LogAttributes &attrlist)
{
	auto attrs = AMF0::Object();

	for(auto it = attrlist.begin(); it != attrlist.end(); it++)
		attrs->putValueAtKey(it->second, it->first);

	attrs
		->putValueAtKey(AMF0::Number(pid), "@pid")
		->putValueAtKey(AMF0::String(serverId), "@server")
		->putValueAtKey(AMF0::Number(unixCurrentTime()), "@timestamp")
		->putValueAtKey(AMF0::String(type), "@type")
	;

	printf("%s\n", attrs->toJSON(0).c_str());
}

struct NetStream : public Object {
	enum State { NS_IDLE, NS_PUBLISHING, NS_PLAYING };

	NetStream() = delete;

	NetStream(std::shared_ptr<Client> owner, uint32_t streamID) : m_owner(owner), m_streamID(streamID)
	{
		resetPlayParams();
	}

	void resetPlayParams()
	{
		m_audioLifetime = audioLifetime;
		m_videoLifetime = videoLifetime;
		m_finishByMargin = finishByMargin;
		m_expirePreviousGop = expirePreviousGop;
		m_previousGopStartByMargin = previousGopStartByMargin;
		m_seenKeyframe = false;
	}

	static void trySetTimeParam(Time *dst, const std::map<std::string, std::string> &params, const std::string &key, Time defaultSetting)
	{
		auto it = params.find(key);
		if(it != params.end())
		{
			Time timeValue = paramValueToFloat(it->second, -1);
			if(timeValue >= 0.0)
			{
				Time max = std::max(Time(10.0), defaultSetting * 2); // safety to avoid buffering too much
				*dst = std::min(timeValue, max);

				if(verbose) printf("set play param %s to %f\n", key.c_str(), (double)*dst);
			}
		}
	}

	void overridePlayParams(const std::string &queryStr)
	{
		auto params = splitParams(queryStr, "&?;");

		trySetTimeParam(&m_audioLifetime, params, "audioLifetime", audioLifetime);
		trySetTimeParam(&m_videoLifetime, params, "videoLifetime", videoLifetime);
		trySetTimeParam(&m_finishByMargin, params, "finishByMargin", finishByMargin);
		trySetTimeParam(&m_previousGopStartByMargin, params, "previousGopStartByMargin", previousGopStartByMargin);

		if(params.count("expirePreviousGop"))
		{
			auto v = params["expirePreviousGop"];
			m_expirePreviousGop = not ((v == "0") or (v == "no") or (v == "false"));
			if(verbose) printf("set expirePreviousGop to %s\n", m_expirePreviousGop ? "yes" : "no");
		}

		if(params.count("asis"))
		{
			auto v = params["asis"];
			m_adjustTimestamps = ((v == "0") or (v == "no") or (v == "false"));
			if(verbose) printf("set asis to %s\n", m_adjustTimestamps ? "no" : "yes");
		}
		else
			m_adjustTimestamps = true;

		if(not m_adjustTimestamps)
			m_timestampOffset = m_highestTimestamp = m_minTimestamp = 0;
	}

	Time updateTimeAccounting(bool wrappingUp)
	{
		Time now = mainRL.getCurrentTime();
		Time delta = now - m_lastStreamAcctTime;
		if((delta >= streamAccountingMin) or wrappingUp)
		{
			m_lastStreamAcctTime = wrappingUp ? -INFINITY : now;
			if(delta < streamAccountingMax)
			{
				m_streamDuration += delta;
				return delta;
			}
		}
		return 0.0;
	}

	void resetTimeAccounting()
	{
		m_streamDuration = 0.0;
		m_lastStreamAcctTime = -INFINITY;
	}

	void expireChain()
	{
		m_chain.expire(
			m_expirePreviousGop ? mainRL.getCurrentTime() + m_previousGopStartByMargin : INFINITY,
			m_expirePreviousGop ? mainRL.getCurrentTime() + m_finishByMargin : INFINITY);
	}

	std::shared_ptr<Client> m_owner;
	State m_state { NS_IDLE };
	uint32_t m_streamID;
	std::string m_name;
	std::string m_hashname;
	std::string m_query;
	uint32_t m_timestampOffset { 0 };
	uint32_t m_highestTimestamp { 0 };
	uint32_t m_minTimestamp { 0 };
	bool m_restarted { false };
	bool m_seenKeyframe { false };
	bool m_adjustTimestamps { true };
	bool m_paused { false };
	bool m_receiveVideo { true };
	bool m_receiveAudio { true };
	Time m_audioLifetime;
	Time m_videoLifetime;
	Time m_finishByMargin;
	Time m_previousGopStartByMargin;
	Time m_streamDuration { 0.0 };
	Time m_lastStreamAcctTime { -INFINITY };
	bool m_expirePreviousGop;
	WriteReceiptChain m_chain;
};

struct Stream {
	bool m_publishing { false };
	std::shared_ptr<NetStream> m_publisher;
	std::set<std::shared_ptr<NetStream>> m_subscribers;
	std::map<std::string, Bytes> m_dataFrames; // Bytes includes callback name
	Bytes m_videoInit;
	Bytes m_audioInit;
	Bytes m_lastVideoKeyframe;
	Bytes m_videoMetadataBeforeInit; // Enhanced RTMP https://github.com/veovera/enhanced-rtmp
	Bytes m_videoMetadataLatest; // Enhanced RTMP
	Bytes m_audioMultichannelConfigBeforeInit; // Enhanced RTMP
	Bytes m_audioMultichannelConfigLatest; // Enhanced RTMP
	uint32_t m_lastVideoTimestamp { 0 };
	uint32_t m_lastVideoCodec { UINT32_C(0xffffffff) };
	uint32_t m_lastAudioCodec { UINT32_C(0xffffffff) };
	double m_priority { 0 };
	bool m_lastVideoFrameWasKey { false };

	void unpublishClear()
	{
		m_publishing = false;
		m_publisher.reset();
		m_dataFrames.clear();
		m_videoInit.clear();
		m_audioInit.clear();
		m_lastVideoKeyframe.clear();
		m_videoMetadataBeforeInit.clear();
		m_videoMetadataLatest.clear();
		m_audioMultichannelConfigBeforeInit.clear();
		m_audioMultichannelConfigLatest.clear();
		m_lastVideoTimestamp = 0;
		m_lastVideoCodec = UINT32_C(0xffffffff);
		m_lastAudioCodec = UINT32_C(0xffffffff);
		m_lastVideoFrameWasKey = false;
	}
};

class App : public Object {
public:
	App(const std::string &name) : m_name(name)
	{
		jsonLog("create-app", {{"app", AMF0::String(m_name)}});
	}

	~App()
	{
		jsonLog("destroy-app", {
			{"app", AMF0::String(m_name)},
			{"connects", AMF0::Number(m_connectCount)},
			{"maxClients", AMF0::Number(m_maxClients)},
			{"publishes", AMF0::Number(m_publishCount)},
			{"plays", AMF0::Number(m_subscribeCount)},
			{"relaysIn", AMF0::Number(m_relaysIn)},
			{"relaysOut", AMF0::Number(m_relaysOut)},
			{"broadcasts", AMF0::Number(m_broadcastCount)},
			{"playedDuration", AMF0::Number(::round(m_playedDuration))},
			{"publishedDuration", AMF0::Number(::round(m_publishedDuration))}
		});
	}

	static bool isHashName(const std::string &name)
	{
		return 0 == name.compare(0, 7, "sha256:");
	}

	static std::string asHashName(const std::string &name)
	{
		if(isHashName(name))
			return name;

		uint8_t md[32];
		flashcrypto->sha256(md, name.data(), name.size());

		return std::string("sha256:") + Hex::encode(md, sizeof(md));
	}

	// implementations below in "--- App" section
	static std::shared_ptr<App> getApp(const std::string &name);
	void addClient(std::shared_ptr<Client> client, const std::string &username, bool isExclusive);
	void removeClient(std::shared_ptr<Client> client, const std::string &username);
	void broadcastMessage(Client *sender, const Bytes &message);
	void sendShutdownNotify();

	void subscribeStream(const std::string &hashname, std::shared_ptr<NetStream> netStream);
	void unsubscribeStream(const std::string &hashname, std::shared_ptr<NetStream> netStream);

	bool publishStream(const std::string &hashname, std::shared_ptr<NetStream> netStream, double publishPriority); // false means stream was already being published and wasn't preempted
	void unpublishStream(const std::string &hashname);
	void releaseStream(const std::string &hashname, double publishPriority);

	void onStreamMessage(const std::string &hashname, uint8_t messageType, uint32_t timestamp, const uint8_t *payload, size_t len);

	static bool isVideoCheckpointCommand(const uint8_t *payload, size_t len);
	static bool isVideoSequenceSpecial(const uint8_t *payload, size_t len);

	size_t m_relaysIn { 0 };
	size_t m_relaysOut { 0 };
	Time   m_publishedDuration { 0.0 };
	Time   m_playedDuration { 0.0 };
protected:
	void cleanupStream(const std::string &hashname);

	size_t m_connectCount { 0 };
	size_t m_publishCount { 0 };
	size_t m_subscribeCount { 0 };
	size_t m_broadcastCount { 0 };
	size_t m_maxClients { 0 };

	std::set<std::shared_ptr<Client>> m_clients;
	std::string m_name;
	std::map<std::string, Stream> m_streams; // by hashname
	std::map<std::string, std::shared_ptr<Client>> m_exclusiveClients; // by username
};
std::map<std::string, std::shared_ptr<App>> apps;

class Client : public Object {
public:
	static void updateRedirectorLoadFactor()
	{
		for(auto it = redirectors.begin(); it != redirectors.end(); it++)
			(*it)->setLoadFactor(clients.size());
	}

	static void onUnmatchedIHello(RTMFP *rtmfp, const void *epd, size_t epdLen, const void *tag, size_t tagLen, int interfaceID, const struct sockaddr *srcAddr)
	{
		FlashCryptoAdapter::EPDParseState epdParsed;
		if(not epdParsed.parse((const uint8_t *)epd, epdLen))
			return;
		if(not epdParsed.fingerprint)
			return;

		Address addr(srcAddr);
		addr.setOrigin(Address::ORIGIN_OBSERVED);

		if(verbose) jsonLog("lookup", {
			{"address", AMF0::String(addr.toPresentation())},
			{"target", AMF0::String(Hex::encode(epdParsed.fingerprint, epdParsed.fingerprintLen))}
		});
		lookupCount++;

		auto it = clients.find(Bytes(epdParsed.fingerprint, epdParsed.fingerprint + epdParsed.fingerprintLen));
		if(it != clients.end())
			it->second->doRedirect(rtmfp, epd, epdLen, tag, tagLen, interfaceID, addr);
	}

	virtual void doRedirect(RTMFP *rtmfp, const void *epd, size_t epdLen, const void *tag, size_t tagLen, int interfaceID, const Address &addr)
	{
	}

	virtual void close()
	{
		clientLog("closing", {});

		m_open = false;

		if(m_disconnectTimer)
			m_disconnectTimer->cancel();
		m_disconnectTimer.reset();

		for(auto it = m_netStreams.begin(); it != m_netStreams.end(); it++)
			closeStream(it->second);
		m_netStreams.clear();

		auto myself = share_ref(this);
		for(auto it = m_watchedBy.begin(); it != m_watchedBy.end(); it++)
			(*it)->onWatchedClientDidClose(myself);
		m_watchedBy.clear();
		for(auto it = m_watching.begin(); it != m_watching.end(); it++)
			(*it)->onWatchingClientDidClose(myself);
		m_watching.clear();

		if(m_app)
			m_app->removeClient(myself, m_username);
		m_app.reset();

		// log after tearing everything down to catch all accounting
		clientLog("close", {
			{"publishes", AMF0::Number(m_publishes)},
			{"plays", AMF0::Number(m_subscribes)},
			{"broadcasts", AMF0::Number(m_broadcasts)},
			{"relaysIn", AMF0::Number(m_relaysIn)},
			{"relaysOut", AMF0::Number(m_relaysOut)},
			{"publishedDuration", AMF0::Number(::round(m_publishedDuration))},
			{"playedDuration", AMF0::Number(::round(m_playedDuration))}
		});
		showStats = true;
	}

	virtual std::shared_ptr<WriteReceipt> write(uint32_t streamID, uint8_t messageType, uint32_t timestamp, const void *payload, size_t len, Time startWithin, Time finishWithin) = 0;

	std::shared_ptr<WriteReceipt> write(uint32_t streamID, uint8_t messageType, uint32_t timestamp, const Bytes &payload, Time startWithin, Time finishWithin)
	{
		return write(streamID, messageType, timestamp, payload.data(), payload.size(), startWithin, finishWithin);
	}

	void sendRelay(Client *sender, const Bytes &message)
	{
		auto header = AMF0::Object();
		header->putValueAtKey(AMF0::String(sender->connectionIDStr()), "sender");
		if((not sender->m_publishUsername.empty()) and (sender->m_appName == m_appName))
			header->putValueAtKey(AMF0::String(sender->m_publishUsername), "senderName");

		Bytes payload;
		header->encode(payload);
		payload.insert(payload.end(), message.begin(), message.end());
		write(0, TCMSG_COMMAND, 0, Message::command("onRelay", 0, nullptr, payload), INFINITY, INFINITY);
		relaysOut++;
		m_relaysOut++;
		m_app->m_relaysOut++;
	}

	void relayStreamMessage(std::shared_ptr<NetStream> netStream, uint8_t messageType, uint32_t timestamp, const uint8_t *payload, size_t len)
	{
		assert(NetStream::NS_PLAYING == netStream->m_state);

		uint32_t adjustedTimestamp = timestamp - netStream->m_timestampOffset;

		if(netStream->m_adjustTimestamps)
		{
			if( (netStream->m_restarted)
			 or (Message::timestamp_lt(adjustedTimestamp, netStream->m_highestTimestamp - timestampAdjustmentMargin))
			 or (Message::timestamp_gt(adjustedTimestamp, netStream->m_highestTimestamp + timestampAdjustmentMargin))
			)
			{
				adjustedTimestamp = netStream->m_highestTimestamp;
				netStream->m_timestampOffset = timestamp - adjustedTimestamp;
				netStream->m_minTimestamp = adjustedTimestamp;
			}

			if(Message::timestamp_lt(adjustedTimestamp, netStream->m_minTimestamp))
				adjustedTimestamp = netStream->m_minTimestamp;
		}
		else if((0 == netStream->m_minTimestamp) and (0 == netStream->m_highestTimestamp) and (Message::timestamp_lt(timestamp, 0)))
		{
			// this only happens if we're tuning in to a stream with current timestamps > 2^31.
			netStream->m_highestTimestamp = timestamp;
			netStream->m_minTimestamp = timestamp - 3600000;
		}

		if(timestamp and Message::timestamp_gt(adjustedTimestamp, netStream->m_highestTimestamp))
			netStream->m_highestTimestamp = adjustedTimestamp;
		if(Message::timestamp_lt(netStream->m_minTimestamp, netStream->m_highestTimestamp - 3600000))
			netStream->m_minTimestamp = netStream->m_highestTimestamp - 3600000; // one hour

		netStream->m_restarted = false;

		Time startWithin = INFINITY;
		bool isVideoCodingLayer = false;

		switch(messageType)
		{
		case TCMSG_VIDEO:
			if(not App::isVideoSequenceSpecial(payload, len))
			{
				if(netStream->m_paused or not netStream->m_receiveVideo)
					return;
				if(App::isVideoCheckpointCommand(payload, len))
					startWithin = checkpointLifetime;
				else
				{
					startWithin = netStream->m_videoLifetime;
					isVideoCodingLayer = true;

					if(not netStream->m_seenKeyframe)
					{
						if(Message::isVideoKeyframe(payload, len))
							netStream->m_seenKeyframe = true;
						else
							return; // drop VCL messages until first keyframe
					}
				}
			}
			break;

		case TCMSG_AUDIO:
			if(not Message::isAudioSequenceSpecial(payload, len))
			{
				if(netStream->m_paused or not netStream->m_receiveAudio)
					return;
				startWithin = netStream->m_audioLifetime;
			}
			break;

		default:
			break;
		}

		auto rv = write(netStream->m_streamID, messageType, adjustedTimestamp, payload, len, startWithin, startWithin + netStream->m_finishByMargin);

		if(isVideoCodingLayer and rv)
		{
			if(Message::isVideoKeyframe(payload, len))
				netStream->expireChain();
			netStream->m_chain.append(rv);
		}

		if(verbose and rv)
			rv->onFinished = [] (bool abandoned) { if(abandoned) { printf("-"); fflush(stdout); } };

		updatePlayedDuration(netStream->updateTimeAccounting(false));
	}

	void relayStreamMessage(std::shared_ptr<NetStream> netStream, uint8_t messageType, uint32_t timestamp, const Bytes &payload)
	{
		return relayStreamMessage(netStream, messageType, timestamp, payload.data(), payload.size());
	}

	void sendPublishNotify(std::shared_ptr<NetStream> netStream, const Stream &stream)
	{
		netStream->m_restarted = true;
		if(not netStream->m_adjustTimestamps)
		{
			netStream->m_highestTimestamp = 0;
			netStream->m_minTimestamp = 0;
			netStream->m_timestampOffset = 0;
		}

		auto infoObject = AMF0::Object();
		infoObject
				->putValueAtKey(AMF0::String("status"), "level")
				->putValueAtKey(AMF0::String("NetStream.Play.PublishNotify"), "code")
				->putValueAtKey(AMF0::String(netStream->m_name), "detail")
				->putValueAtKey(AMF0::String(netStream->m_hashname), "hashname")
				->putValueAtKey(AMF0::String("being published"), "description")
				->putValueAtKey(AMF0::Number(stream.m_priority), "priority")
				->putValueAtKey(AMF0::String(stream.m_publisher->m_owner->connectionIDStr()), "publisher");
		if(not stream.m_publisher->m_owner->m_publishUsername.empty())
			infoObject->putValueAtKey(AMF0::String(stream.m_publisher->m_owner->m_publishUsername), "publisherName");

		auto onStatusMessage = Message::command("onStatus", 0, nullptr, infoObject);
		relayStreamMessage(netStream, TCMSG_COMMAND, 0, onStatusMessage);

		for(auto it = stream.m_dataFrames.begin(); it != stream.m_dataFrames.end(); it++)
			relayStreamMessage(netStream, TCMSG_DATA, 0, it->second);

		if(not stream.m_audioMultichannelConfigBeforeInit.empty())
			relayStreamMessage(netStream, TCMSG_AUDIO, 0, stream.m_audioMultichannelConfigBeforeInit);
		if(not stream.m_audioInit.empty())
			relayStreamMessage(netStream, TCMSG_AUDIO, 0, stream.m_audioInit);
		if(not stream.m_audioMultichannelConfigLatest.empty())
			relayStreamMessage(netStream, TCMSG_AUDIO, 0, stream.m_audioMultichannelConfigLatest);
		if(not stream.m_videoMetadataBeforeInit.empty()) // RTMP Enhanced Video Metadata that goes before Sequence Start/Init
			relayStreamMessage(netStream, TCMSG_VIDEO, 0, stream.m_videoMetadataBeforeInit);
		if(not stream.m_videoInit.empty())
			relayStreamMessage(netStream, TCMSG_VIDEO, 0, stream.m_videoInit);
		if(not stream.m_videoMetadataLatest.empty()) // Latest RTMP Enhanced Video Metadata goes after Sequence Start/Init
			relayStreamMessage(netStream, TCMSG_VIDEO, 0, stream.m_videoMetadataLatest);

		netStream->m_restarted = true;
		if(not stream.m_lastVideoKeyframe.empty())
		{
			relayStreamMessage(netStream, TCMSG_VIDEO, stream.m_lastVideoTimestamp, stream.m_lastVideoKeyframe);

			if(not stream.m_lastVideoFrameWasKey)
			{
				// not all codecs work well if you replay the last keyframe and then
				// start sending predicted frames with missing intervening frames.

				switch(stream.m_lastVideoCodec)
				{
				case TC_VIDEO_CODEC_SPARK:
				case TC_VIDEO_CODEC_SCREEN:
				case TC_VIDEO_CODEC_VP6:
				case TC_VIDEO_CODEC_VP6_ALPHA:
				case TC_VIDEO_CODEC_SCREEN_V2:
				case TC_VIDEO_CODEC_AVC:
				case TC_VIDEO_ENH_CODEC_AVC:
					// these codecs seem to work ok though.
					break;

				default:
					relayStreamMessage(netStream, TCMSG_VIDEO, stream.m_lastVideoTimestamp, Message::makeVideoEndOfSequence(stream.m_lastVideoCodec));
					netStream->m_seenKeyframe = false;
					break;
				}
			}
		}
	}

	void sendUnpublishNotify(std::shared_ptr<NetStream> netStream)
	{
		syncAudioAndData(netStream->m_streamID);

		write(netStream->m_streamID, TCMSG_COMMAND, netStream->m_highestTimestamp, Message::command("onStatus", 0, nullptr,
			AMF0::Object()
				->putValueAtKey(AMF0::String("status"), "level")
				->putValueAtKey(AMF0::String("NetStream.Play.UnpublishNotify"), "code")
				->putValueAtKey(AMF0::String(netStream->m_name), "detail")
				->putValueAtKey(AMF0::String(netStream->m_hashname), "hashname")
				->putValueAtKey(AMF0::String("publish stop"), "description")
			), INFINITY, INFINITY);

		syncAudioAndData(netStream->m_streamID);

		updatePlayedDuration(netStream->updateTimeAccounting(true));
	}

	void releaseStream(std::shared_ptr<NetStream> netStream)
	{
		assert(NetStream::NS_PUBLISHING == netStream->m_state);

		write(netStream->m_streamID, TCMSG_COMMAND, 0, Message::command("onStatus", 0, nullptr,
			AMF0::Object()
				->putValueAtKey(AMF0::String("error"), "level")
				->putValueAtKey(AMF0::String("NetStream.Publish.BadName"), "code")
				->putValueAtKey(AMF0::String("publish terminated by releaseStream"), "description")
				->putValueAtKey(AMF0::String(netStream->m_name), "detail")
				->putValueAtKey(AMF0::String(netStream->m_hashname), "hashname")
			), INFINITY, INFINITY);

		closeStream(netStream);
	}

	virtual Bytes getNearNonce()
	{
		return Bytes();
	}

	virtual Bytes getFarNonce()
	{
		return Bytes();
	}

	void sendShutdownNotify()
	{
		write(0, TCMSG_COMMAND, 0, Message::command("onStatus", 0, nullptr,
			AMF0::Object()
				->putValueAtKey(AMF0::String("status"), "level")
				->putValueAtKey(AMF0::String("NetConnection.Shutdown.Notify"), "code") // not NetConnection.Connect.AppShutdown
				->putValueAtKey(AMF0::String("server is shutting down, please clean up"), "description")
			), INFINITY, INFINITY);
	}

protected:
	void setRandomConnectionID()
	{
		assert(0 == m_connectionID.size());

		m_connectionID.resize(24);
		flashcrypto->pseudoRandomBytes(m_connectionID.data(), m_connectionID.size());
	}

	std::string connectionIDStr() const
	{
		return Hex::encode(m_connectionID);
	}

	void onShutdownComplete()
	{
		m_finished = true;
		clients.erase(m_connectionID);
		updateRedirectorLoadFactor();
	}

	void onMessage(uint32_t streamID, uint8_t messageType, uint32_t timestamp, const uint8_t *payload, size_t len)
	{
		if(verbose > 1)
		{
			clientLog("debug-stream", {
				{"stringID", AMF0::Number(streamID)},
				{"messageType", AMF0::Number(messageType)},
				{"messageTimestamp", AMF0::Number(timestamp)},
				{"messageLength", AMF0::Number(len)}
			});
			fflush(stdout);
		}

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
			onStreamMessage(streamID, messageType, timestamp, payload, len);
			break;

		default:
			break;
		}
	}

	void onCommandMessage(uint32_t streamID, uint8_t messageType, const uint8_t *payload, size_t len)
	{
		const uint8_t *cursor = payload;
		const uint8_t *limit = cursor + len;

		if(0 == len)
			return;
		if((TCMSG_COMMAND_EX == messageType) and (0 != *cursor++)) // COMMAND_EX has a format id, and only format id=0 is defined
			return;

		Args args;
		if(not AMF0::decode(cursor, limit, args))
		{
			if(verbose > 2)
				Hex::print("Client::onCommandMessage() couldn't fully decode command arguments", cursor, limit);
		}
		if(verbose > 1)
		{
			printf("TCMSG_COMMAND%s\n", TCMSG_COMMAND_EX == messageType ? "_EX" : "");
			for(auto it = args.begin(); it != args.end(); it++)
				printf("  %s\n", (*it)->repr().c_str());
		}

		if( (args.size() < 2)
		 or (not args[0]->isString()) // command name
		 or (not args[1]->isNumber()) // transaction ID
		)
		{
			clientLog("error", {{"reason", AMF0::String("invalid-command-format")}});
			close();
			return;
		}

		if(0 == streamID)
			onControlCommand(args);
		else
			onStreamCommand(streamID, args);
	}

	void onControlCommand(const Args &args)
	{
		const char *commandName = args[0]->stringValue();

		if(0 == strcmp("connect", commandName))
		{
			onConnectCommand(args);
			return;
		}

		if(not m_connected)
		{
			clientLog("error", {{"reason", AMF0::String("command-before-connect")}});
			close();
			return;
		}

		if(0 == strcmp("createStream", commandName))
			onCreateStreamCommand(args);
		else if(0 == strcmp("deleteStream", commandName))
			onDeleteStreamCommand(args);
		else if(0 == strcmp("relay", commandName))
			onRelayCommand(args);
		else if(0 == strcmp("broadcast", commandName))
			onBroadcastCommand(args);
		else if(0 == strcmp("setPeerInfo", commandName))
			onSetPeerInfoCommand(args);
		else if(0 == strcmp("watch", commandName))
			onWatchCommand(args);
		else if(0 == strcmp("releaseStream", commandName))
			onReleaseStreamCommand(args);
		else if(0 == strcmp("FCPublish", commandName))
			ackCommandTransaction(args); // ignore
		else if(0 == strcmp("FCUnpublish", commandName))
			ackCommandTransaction(args); // ignore
		else
			onUnknownCommand(args);
	}

	void onStreamCommand(uint32_t streamID, const Args &args)
	{
		auto it = m_netStreams.find(streamID);
		if(m_netStreams.end() == it)
		{
			close();
			return;
		}

		const char *commandName = args[0]->stringValue();
		auto netStream = it->second;

		if(0 == strcmp("publish", commandName))
			onPublishCommand(netStream, args);
		else if(0 == strcmp("play", commandName))
			onPlayCommand(netStream, args);
		else if(0 == strcmp("closeStream", commandName))
			closeStream(netStream);
		else if(0 == strcmp("pause", commandName))
			onPauseCommand(netStream, args);
		else if(0 == strcmp("receiveVideo", commandName))
			onReceiveVideoCommand(netStream, args);
		else if(0 == strcmp("receiveAudio", commandName))
			onReceiveAudioCommand(netStream, args);
	}

	std::string authChallengeForArgs(const Args &args)
	{
		if((args.size() > 4) and args[3]->isString() and args[4]->isString())
			return std::string(args[3]->stringValue()) + "@" + m_appName;
		return m_appName;
	}

	int validateAuth(const Args &args)
	{
		if((args.size() < 4) or not args[3]->isString())
			return -1;

		std::string authChallenge = authChallengeForArgs(args);
		std::string authToken = args[((args.size() > 4) and args[4]->isString()) ? 4 : 3]->stringValue();;

		Bytes nearNonce = getNearNonce();

		for(size_t x = 0; x < secrets.size(); x++)
		{
			std::string expectedAuth = hexHMACSHA256(secrets[x], authChallenge);
			if(expectedAuth == authToken)
				return x;

			if((not nearNonce.empty()) and (hexHMACSHA256(nearNonce, expectedAuth) == authToken))
				return x;
		}
		return -1;
	}

	void onConnectCommand(const Args &args)
	{
		if(args.size() < 3)
		{
			clientLog("error", {{"reason", AMF0::String("connect-missing-arg")}});
			close();
			return;
		}

		if(m_connecting)
		{
			clientLog("error", {{"reason", AMF0::String("connect-after-connect")}});
			close();
			return;
		}
		m_connecting = true;

		auto app = args[2]->getValueAtKey("app");
		if(not app->isString())
		{
			auto tcUrl = args[2]->getValueAtKey("tcUrl");
			if(not tcUrl->isString())
			{
				clientLog("error", {{"reason", AMF0::String("connect-missing-app-and-tcUrl")}});
				close();
				return;
			}

			URIParse uri(tcUrl->stringValue());
			app = AMF0::String(uri.path.substr(0, 1) == "/" ? uri.path.substr(1) : uri.path);
		}
		m_appName = URIParse::safePercentDecode(URIParse::split(app->stringValue(), '?', 2)[0]);

		int matchedKey = -1;
		if(secrets.size())
		{
			matchedKey = validateAuth(args);
			if(matchedKey < 0)
			{
				clientLog("connect-reject", {{"reason", AMF0::String("bad-auth")}, {"requestedApp", app}});

				write(0, TCMSG_COMMAND, 0, Message::command("_error", args[1]->doubleValue(), nullptr,
					AMF0::Object()
						->putValueAtKey(AMF0::String("error"), "level")
						->putValueAtKey(AMF0::String("NetConnection.Connect.Rejected"), "code")
						->putValueAtKey(AMF0::String("auth required"), "description")
					), INFINITY, INFINITY);

				close();
				return;
			}

			if((args.size() > 4) and args[3]->isString() and args[4]->isString()) // username & password & authenticated
			{
				m_username = args[3]->stringValue();
				configureUser(m_username);
			}
		}

		if(m_disconnectAfter <= 0)
		{
			close();
			return;
		}
		else if(m_disconnectAfter < INFINITY)
			m_disconnectTimer = mainRL.scheduleRel(Timer::makeAction([this] { close(); }), m_disconnectAfter);

		auto objectEncoding = args[2]->getValueAtKey("objectEncoding");
		if(not objectEncoding->isNumber())
			objectEncoding = AMF0::Number(0);

		const uint8_t CAN_FORWARD = 4;

		auto resultObject = AMF0::Object();
		resultObject
			->putValueAtKey(AMF0::String("status"), "level")
			->putValueAtKey(AMF0::String("NetConnection.Connect.Success"), "code")
			->putValueAtKey(AMF0::String("you connected!"), "description")
			->putValueAtKey(AMF0::String(connectionIDStr()), "connectionID")
			->putValueAtKey(objectEncoding, "objectEncoding")
			->putValueAtKey(AMF0::Number(0), "capsEx") // no support for multitrack or reconnect
			->putValueAtKey(AMF0::Object()->putValueAtKey(AMF0::Number(CAN_FORWARD), "*"), "videoFourCcInfoMap")
			->putValueAtKey(AMF0::Object()->putValueAtKey(AMF0::Number(CAN_FORWARD), "*"), "audioFourCcInfoMap")
			->putValueAtKey(AMF0::Array()->appendValue(AMF0::String("*")), "fourCcList")
			->putValueAtKey(AMF0::String(Hex::encode(flashcrypto->getFingerprint())), "serverFingerprint");

		if(matchedKey >= 0)
		{
			Bytes farNonce = getFarNonce();
			if(not farNonce.empty())
				resultObject->putValueAtKey(AMF0::String(hexHMACSHA256(farNonce, hexHMACSHA256(secrets[matchedKey], authChallengeForArgs(args)))), "authToken");
		}

		if(serverInfo)
			resultObject->putValueAtKey(AMF0::String(serverInfo), "serverInfo");

		write(0, TCMSG_COMMAND, 0, Message::command("_result", args[1]->doubleValue(), nullptr, resultObject), INFINITY, INFINITY);

		m_app = App::getApp(m_appName);
		m_app->addClient(share_ref(this), m_username, m_exclusiveConnection);

		m_connected = true;

		clientLog("connect", {{"tcUrl", args[2]->getValueAtKey("tcUrl")}, {"connectArg", m_username.empty() ? nullptr : AMF0::String(m_username)}});
		connectCount++;
		showStats = true;

		if(shuttingDown)
			sendShutdownNotify();
	}

	void onCreateStreamCommand(const Args &args)
	{
		if(m_netStreams.size() >= maxNetStreamsPerClient)
		{
			close(); // abusive
			return;
		}

		uint32_t streamID;
		do {
			streamID = (m_nextStreamID++ & UINT32_C(0xffffff));
		} while((0 == streamID) or m_netStreams.count(streamID));

		m_netStreams[streamID] = share_ref(new NetStream(share_ref(this), streamID), false);

		clientLog("createStream", {{"streamID", AMF0::Number(streamID)}});

		write(0, TCMSG_COMMAND, 0, Message::command("_result", args[1]->doubleValue(), nullptr, AMF0::Number(streamID)), INFINITY, INFINITY);
	}

	void onDeleteStreamCommand(const Args &args)
	{
		ackCommandTransaction(args);

		if((args.size() < 4) or (not args[3]->isNumber()))
			return;
		uint32_t streamID = (uint32_t)args[3]->doubleValue();
		auto it = m_netStreams.find(streamID);
		if(it != m_netStreams.end())
		{
			closeStream(it->second);
			clientLog("deleteStream", {{"streamID", AMF0::Number(streamID)}});
			m_netStreams.erase(streamID);
			deleteStreamTransport(streamID);
		}
	}

	void onRelayCommand(const Args &args)
	{
		ackCommandTransaction(args);

		// TODO rate limit

		Bytes dst;
		if((args.size() < 4) or (not args[3]->isString()) or not Hex::decode(args[3]->stringValue(), dst))
			return; // args[3] is destination in hex

		auto it = clients.find(dst);
		if(it == clients.end())
		{
			clientLog("relay", {{"found", AMF0::False()}});
			return;
		}

		Bytes msg;
		for(size_t x = 4; x < args.size(); x++)
			args[x]->encode(msg);

		clientLog("relay", {
			{"found", AMF0::True()},
			{"target", AMF0::String(it->second->connectionIDStr())},
			{"targetAddress", AMF0::String(it->second->m_farAddressStr)}
		});
		relaysIn++;
		m_relaysIn++;
		m_app->m_relaysIn++;

		it->second->sendRelay(this, msg);
	}

	void onBroadcastCommand(const Args &args)
	{
		ackCommandTransaction(args);

		// TODO rate limit

		Bytes msg;
		for(size_t x = 3; x < args.size(); x++)
			args[x]->encode(msg);

		clientLog("broadcast", {});
		broadcastCount++;
		m_broadcasts++;

		m_app->broadcastMessage(this, msg);
	}

	virtual void onSetPeerInfoCommand(const Args &args)
	{
		ackCommandTransaction(args);
	}

	void onWatchCommand(const Args &args)
	{
		ackCommandTransaction(args);

		if(args.size() < 4)
			return; // args[3] is target connectionID in hex

		Bytes target;
		if((not args[3]->isString()) or not Hex::decode(args[3]->stringValue(), target))
		{
			clientLog("watch", {{"status", AMF0::String("malformed")}});
			write(0, TCMSG_COMMAND, 0, Message::command("onDisconnected", 0, nullptr, args[3]), INFINITY, INFINITY);
			return;
		}

		auto it = clients.find(target);
		if(it == clients.end())
		{
			sendOnDisconnected(target);
			clientLog("watch", {{"status", AMF0::String("not-found")}});
			return;
		}

		if(it->second.get() == this)
		{
			clientLog("watch", {{"status", AMF0::String("self")}});
			return;
		}

		clientLog("watch", {
			{"status", AMF0::String("found")},
			{"targetAddress", AMF0::String(it->second->m_farAddressStr)},
			{"target", args[3]}
		});

		m_watching.insert(it->second);
		it->second->onWatchRequest(share_ref(this));
	}

	void onReleaseStreamCommand(const Args &args)
	{
		ackCommandTransaction(args);

		if((args.size() < 4) or not args[3]->isString())
			return;

		std::string publishName = args[3]->stringValue();
		std::string hashname = App::asHashName(publishName);

		clientLog("releaseStream", {{"name", AMF0::String(publishName)}, {"hashname", AMF0::String(hashname)}});

		if((App::isHashName(publishName)) or (0 == publishName.compare(0, 5, "asis:")))
			return;

		m_app->releaseStream(hashname, m_maxPublishPriority);
	}

	void ackCommandTransaction(const Args &args)
	{
		if(args[1]->doubleValue() > 0.0)
			write(0, TCMSG_COMMAND, 0, Message::command("_result", args[1]->doubleValue(), nullptr, AMF0::Undefined()), INFINITY, INFINITY);
	}

	void onUnknownCommand(const Args &args)
	{
		write(0, TCMSG_COMMAND, 0, Message::command(
			args[1]->doubleValue() > 0.0 ? "_error" : "onStatus",
			args[1]->doubleValue(),
			nullptr,
			AMF0::Object()
				->putValueAtKey(AMF0::String("error"), "level")
				->putValueAtKey(AMF0::String("NetConnection.Call.Failed"), "code")
				->putValueAtKey(AMF0::String("Method not found"), "description")
				->putValueAtKey(args[0], "detail")
			), INFINITY, INFINITY);
	}

	void logStreamEvent(const char *name, std::shared_ptr<NetStream> netStream)
	{
		clientLog(name, {
			{"streamID", AMF0::Number(netStream->m_streamID)},
			{"name", AMF0::String(netStream->m_name)},
			{"hashname", AMF0::String(netStream->m_hashname)},
			{"query", AMF0::String(netStream->m_query)},
			{"duration", AMF0::Number(::round(netStream->m_streamDuration * 1000.0) / 1000.0)}
		});
	}

	void onPublishCommand(std::shared_ptr<NetStream> netStream, const Args &args)
	{
		closeStream(netStream);

		if((args.size() < 4) or not args[3]->isString())
			return; // empty or non-string publish is unpublish so we're done

		auto publishArgs = URIParse::split(args[3]->stringValue(), "?", 2);

		std::string publishName = publishArgs[0];
		std::string hashname = App::asHashName(publishName);
		std::string publishQuery;

		double publishPriority = -INFINITY;

		if(publishArgs.size() > 1)
		{
			publishQuery = publishArgs[1];
			auto params = splitParams(publishQuery, "&?;");
			if(params.count("priority"))
				publishPriority = std::min(m_maxPublishPriority, double(paramValueToFloat(params["priority"], publishPriority)));
		}

		if( (m_publishingCount >= m_maxPublishingCount)
		 or (App::isHashName(publishName))
		 or (0 == publishName.compare(0, 5, "asis:"))
		 or (not m_app->publishStream(hashname, netStream, publishPriority))
		)
		{
			clientLog("publish-reject", {{"streamID", AMF0::Number(netStream->m_streamID)}, {"name", AMF0::String(publishName)}});

			write(netStream->m_streamID, TCMSG_COMMAND, 0, Message::command("onStatus", 0, nullptr,
				AMF0::Object()
					->putValueAtKey(AMF0::String("error"), "level")
					->putValueAtKey(AMF0::String("NetStream.Publish.BadName"), "code")
					->putValueAtKey(AMF0::String("publish error"), "description")), INFINITY, INFINITY);
			return;
		}

		netStream->m_state = NetStream::NS_PUBLISHING;
		netStream->m_name = publishName;
		netStream->m_hashname = hashname;
		netStream->m_query = publishQuery;
		netStream->resetTimeAccounting();

		m_publishingCount++;
		m_publishes++;

		logStreamEvent("publish", netStream);
		write(netStream->m_streamID, TCMSG_COMMAND, 0, Message::command("onStatus", 0, nullptr,
			AMF0::Object()
				->putValueAtKey(AMF0::String("status"), "level")
				->putValueAtKey(AMF0::String("NetStream.Publish.Start"), "code")
				->putValueAtKey(AMF0::String(publishName), "detail")
				->putValueAtKey(AMF0::String(hashname), "hashname")
				->putValueAtKey(AMF0::String("publishing"), "description")
				->putValueAtKey(AMF0::Number(publishPriority), "priority")
			), INFINITY, INFINITY);
	}

	void onPlayCommand(std::shared_ptr<NetStream> netStream, const Args &args)
	{
		closeStream(netStream);

		if((args.size() < 4) or not args[3]->isString()) // empty or non-string play is unsubscribe so we're done
			return;

		auto playArgs = URIParse::split(args[3]->stringValue(), '?', 2);

		std::string playName = playArgs[0];
		netStream->m_name = playName;
		netStream->m_hashname = App::asHashName(playName);

		netStream->m_state = NetStream::NS_PLAYING;
		netStream->resetPlayParams();
		netStream->resetTimeAccounting();

		if(playArgs.size() > 1)
		{
			netStream->m_query = playArgs[1];
			netStream->overridePlayParams(playArgs[1]);
		}
		else
			netStream->m_query.clear();

		logStreamEvent("play", netStream);

		// apparently this is necessary.
		uint8_t streamBeginCommand[6];
		streamBeginCommand[0] = (TC_USERCONTROL_STREAM_BEGIN >> 8) & 0xff;
		streamBeginCommand[1] = (TC_USERCONTROL_STREAM_BEGIN     ) & 0xff;
		streamBeginCommand[2] = (netStream->m_streamID >> 24) & 0xff;
		streamBeginCommand[3] = (netStream->m_streamID >> 16) & 0xff;
		streamBeginCommand[4] = (netStream->m_streamID >>  8) & 0xff;
		streamBeginCommand[5] = (netStream->m_streamID      ) & 0xff;
		write(0, TCMSG_USER_CONTROL, 0, streamBeginCommand, sizeof(streamBeginCommand), INFINITY, INFINITY);

		write(netStream->m_streamID, TCMSG_COMMAND, 0, Message::command("onStatus", 0, nullptr,
			AMF0::Object()
				->putValueAtKey(AMF0::String("status"), "level")
				->putValueAtKey(AMF0::String("NetStream.Play.Reset"), "code")
				->putValueAtKey(AMF0::String(netStream->m_name), "detail")
				->putValueAtKey(AMF0::String(netStream->m_hashname), "hashname")
				->putValueAtKey(AMF0::String("Reset"), "description")
			), INFINITY, INFINITY);

		write(netStream->m_streamID, TCMSG_COMMAND, 0, Message::command("onStatus", 0, nullptr,
			AMF0::Object()
				->putValueAtKey(AMF0::String("status"), "level")
				->putValueAtKey(AMF0::String("NetStream.Play.Start"), "code")
				->putValueAtKey(AMF0::String(netStream->m_name), "detail")
				->putValueAtKey(AMF0::String(netStream->m_hashname), "hashname")
				->putValueAtKey(AMF0::String("Subscribe"), "description")
			), INFINITY, INFINITY);

		// does anything care about this anymore?
		Bytes rtmpSampleAccess;
		AMF0::String("|RtmpSampleAccess")->encode(rtmpSampleAccess);
		AMF0::True()->encode(rtmpSampleAccess);
		AMF0::True()->encode(rtmpSampleAccess);
		write(netStream->m_streamID, TCMSG_DATA, 0, rtmpSampleAccess, INFINITY, INFINITY);

		m_app->subscribeStream(netStream->m_hashname, netStream);
		m_subscribes++;
	}

	void closeStream(std::shared_ptr<NetStream> netStream)
	{
		if(NetStream::NS_PUBLISHING == netStream->m_state)
		{
			assert(m_publishingCount > 0);
			m_publishingCount--;
			netStream->expireChain();
			updatePublishedDuration(netStream->updateTimeAccounting(true));
			logStreamEvent("unpublish", netStream);
			m_app->unpublishStream(netStream->m_hashname);
		}
		else if(NetStream::NS_PLAYING == netStream->m_state)
		{
			updatePlayedDuration(netStream->updateTimeAccounting(true));
			logStreamEvent("unplay", netStream);
			m_app->unsubscribeStream(netStream->m_hashname, netStream);
		}

		netStream->m_state = NetStream::NS_IDLE;
	}

	void onPauseCommand(std::shared_ptr<NetStream> netStream, const Args &args)
	{
		if(args.size() < 4)
			return;
		netStream->m_paused = args[3]->booleanValue();
		if((args.size() > 4) and args[4]->isNumber() and netStream->m_adjustTimestamps and not netStream->m_paused)
		{
			netStream->m_highestTimestamp = (uint32_t)(args[4]->doubleValue());
			netStream->m_restarted = true;
		}
		if(netStream->m_paused)
			netStream->m_seenKeyframe = false;
		logStreamEvent(netStream->m_paused ? "pause" : "unpause", netStream);
	}

	void onReceiveVideoCommand(std::shared_ptr<NetStream> netStream, const Args &args)
	{
		if(args.size() < 4)
			return;
		netStream->m_receiveVideo = args[3]->booleanValue();
		if(not netStream->m_receiveVideo)
			netStream->m_seenKeyframe = false;
		logStreamEvent(netStream->m_receiveVideo ? "receiveVideo,unmute" : "receiveVideo,mute", netStream);
	}

	void onReceiveAudioCommand(std::shared_ptr<NetStream> netStream, const Args &args)
	{
		if(args.size() < 4)
			return;
		netStream->m_receiveAudio = args[3]->booleanValue();
		logStreamEvent(netStream->m_receiveAudio ? "receiveAudio,unmute" : "receiveAudio,mute", netStream);
	}

	void onStreamMessage(uint32_t streamID, uint8_t messageType, uint32_t timestamp, const uint8_t *payload, size_t len)
	{
		auto it = m_netStreams.find(streamID);
		if(it == m_netStreams.end())
			return;

		auto netStream = it->second;
		if(NetStream::NS_PUBLISHING != netStream->m_state)
			return;

		m_app->onStreamMessage(netStream->m_hashname, messageType, timestamp, payload, len);

		updatePublishedDuration(netStream->updateTimeAccounting(false));
	}

	void onWatchedClientDidClose(std::shared_ptr<Client> watched)
	{
		m_watching.erase(watched);
		sendOnDisconnected(watched->m_connectionID);
	}

	void onWatchRequest(std::shared_ptr<Client> watcher)
	{
		m_watchedBy.insert(watcher);
	}

	void onWatchingClientDidClose(std::shared_ptr<Client> watcher)
	{
		m_watchedBy.erase(watcher);
	}

	void sendOnDisconnected(const Bytes &target)
	{
		write(0, TCMSG_COMMAND, 0, Message::command("onDisconnected", 0, nullptr, AMF0::String(Hex::encode(target))), INFINITY, INFINITY);
	}

	virtual void syncAudioAndData(uint32_t streamID)
	{
	}

	virtual void deleteStreamTransport(uint32_t streamID)
	{
	}

	void configureUser(const std::string &configSpec)
	{
		long double unixNow = unixCurrentTime();
		long double notBeforeTime = -INFINITY;
		Time expiresIn = INFINITY;
		long double expiration = INFINITY;
		long double useBy = INFINITY;

		auto params = splitParams(configSpec, ";");

		if(params.count("pri"))
			m_maxPublishPriority = paramValueToFloat(params["pri"], m_maxPublishPriority);
		if(params.count("name"))
			m_publishUsername = params["name"];
		if(params.count("xcl"))
			m_exclusiveConnection = true;
		if(params.count("nbf"))
			notBeforeTime = paramValueToFloat(params["nbf"], notBeforeTime);
		if(params.count("exi"))
			expiresIn = paramValueToFloat(params["exi"], expiresIn);
		if(params.count("exp"))
			expiration = paramValueToFloat(params["exp"], expiration);
		if(params.count("use_by"))
			useBy = paramValueToFloat(params["use_by"], useBy);
		if(params.count("pub"))
			m_maxPublishingCount = (size_t)atoi(params["pub"].c_str());

		if((unixNow < notBeforeTime) or (unixNow > useBy))
			m_disconnectAfter = -1;
		else
			m_disconnectAfter = std::min(expiration - unixNow, expiresIn);
	}

	void updatePublishedDuration(Time delta)
	{
		publishedDuration += delta;
		m_publishedDuration += delta;
		m_app->m_publishedDuration += delta;
	}

	void updatePlayedDuration(Time delta)
	{
		playedDuration += delta;
		m_playedDuration += delta;
		m_app->m_playedDuration += delta;
	}

	void clientLog(const std::string &type, const LogAttributes &attrs)
	{
		auto clientAttrs = attrs;
		clientAttrs.push_back({"connectionID", AMF0::String(connectionIDStr())});
		clientAttrs.push_back({"address", AMF0::String(m_farAddressStr)});
		clientAttrs.push_back({"app", m_connected ? AMF0::String(m_appName) : nullptr});
		clientAttrs.push_back({"proto", AMF0::String(protocol())});
		clientAttrs.push_back({"username", m_publishUsername.empty() ? nullptr : AMF0::String(m_publishUsername)});
		jsonLog(type, clientAttrs);
	}

	virtual std::string protocol() const = 0;

	uint32_t m_nextStreamID { 1 };
	bool m_connecting { false };
	bool m_connected { false };
	bool m_open { true };
	bool m_finished { false };
	bool m_exclusiveConnection { false };
	double m_maxPublishPriority { 0 };
	size_t m_maxPublishingCount { SIZE_MAX };
	size_t m_publishingCount { 0 };
	Time m_disconnectAfter { INFINITY };
	std::string m_publishUsername;
	std::string m_username;
	std::string m_appName;
	size_t m_publishes { 0 };
	size_t m_subscribes { 0 };
	size_t m_broadcasts { 0 };
	size_t m_relaysIn { 0 };
	size_t m_relaysOut { 0 };
	Time m_publishedDuration { 0.0 };
	Time m_playedDuration { 0.0 };
	Bytes m_connectionID;
	Address m_farAddress;
	std::string m_farAddressStr;
	std::shared_ptr<App> m_app;
	std::map<uint32_t, std::shared_ptr<NetStream>> m_netStreams;
	std::set<std::shared_ptr<Client>> m_watching;
	std::set<std::shared_ptr<Client>> m_watchedBy;
	std::shared_ptr<Timer> m_disconnectTimer;
};

class RTMFPClient : public Client {
public:
	static Bytes getPeerID(const std::shared_ptr<RecvFlow> &flow)
	{
		auto epd = flow->getFarCanonicalEPD();
		if((epd.size() == 34) and (0x21 == epd[0]) and (EPD_OPTION_FINGERPRINT == epd[1]))
			return Bytes(epd.data() + 2, epd.data() + epd.size());
		else
			return epd;
	}

	static void newClient(std::shared_ptr<RecvFlow> controlRecv)
	{
		if(shuttingDown and not allowConnectDuringShutdown)
			return;

		uint32_t streamID = 0;
		if((not TCMetadata::parse(controlRecv->getMetadata(), &streamID, nullptr)) or (0 != streamID))
			return; // for now only accept TC flows.

		auto client = share_ref(new RTMFPClient(), false);

		if(allowMultipleConnections)
			client->setRandomConnectionID();
		else
			client->m_connectionID = getPeerID(controlRecv);

		if(clients.count(client->m_connectionID))
			return; // enforce if not allowMultipleConnections

		if(not client->setup(controlRecv))
			return;

		clients[client->m_connectionID] = client;
		updateRedirectorLoadFactor();
	}

	void doRedirect(RTMFP *rtmfp, const void *epd, size_t epdLen, const void *tag, size_t tagLen, int interfaceID, const Address &addr) override
	{
		if((not m_connected) or (not m_setPeerInfoReceived))
			return;

		Client::doRedirect(rtmfp, epd, epdLen, tag, tagLen, interfaceID, addr);

		std::vector<Address> redirectAddresses;
		redirectAddresses.push_back(m_controlRecv->getFarAddress());
		redirectAddresses.insert(redirectAddresses.end(), m_additionalAddresses.begin(), m_additionalAddresses.end());
		rtmfp->sendResponderRedirect(tag, tagLen, redirectAddresses, interfaceID, addr.getSockaddr());

		m_controlRecv->forwardIHello(epd, epdLen, addr, tag, tagLen);

		if(verbose) clientLog("rtmfp-intro", {{"initiator", AMF0::String(addr.toPresentation())}});
		introCount++;
	}

	void close() override
	{
		Client::close();

		if(m_controlSend)
			m_controlSend->close();
		if(m_controlRecv)
			m_controlRecv->close(); // needed for AIR compatibility; this is not good, clean close should be on all RecvFlows closing.

		m_netStreamTransports.clear(); // closes all NetStream SendFlows

		onShutdownComplete();
	}

	using Client::write;

	std::shared_ptr<WriteReceipt> write(uint32_t streamID, uint8_t messageType, uint32_t timestamp, const void *payload, size_t len, Time startWithin, Time finishWithin) override
	{
		if(0 == streamID)
			return m_controlSend->write(TCMessage::message(messageType, timestamp, (const uint8_t *)payload, len), startWithin, finishWithin);

		auto &stream = m_netStreamTransports[streamID]; // create on demand
		return stream.write(m_controlRecv, streamID, messageType, timestamp, (const uint8_t *)payload, len, startWithin, finishWithin);
	}

	Bytes getNearNonce() override
	{
		return m_controlRecv ? m_controlRecv->getNearNonce() : Client::getNearNonce();
	}

	Bytes getFarNonce() override
	{
		return m_controlRecv ? m_controlRecv->getFarNonce() : Client::getFarNonce();
	}

protected:
	struct NetStreamTransport {
		~NetStreamTransport()
		{
			if(m_video) m_video->close();
			if(m_audio) m_audio->close();
			if(m_data) m_data->close();

			for(auto it = m_recvFlows.begin(); it != m_recvFlows.end(); it++)
				(*it)->close();
		}

		SendFlow * openFlowForType(const std::shared_ptr<RecvFlow> &control, uint32_t streamID, uint8_t messageType)
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

		std::shared_ptr<WriteReceipt> write(const std::shared_ptr<RecvFlow> &control, uint32_t streamID, uint8_t messageType, uint32_t timestamp, const uint8_t *payload, size_t len, Time startWithin, Time finishWithin)
		{
			SendFlow *flow = openFlowForType(control, streamID, messageType);
			if(not flow)
				return nullptr;
			return flow->write(TCMessage::message(messageType, timestamp, payload, len), startWithin, finishWithin);
		}

		void syncAudioAndData(uint32_t syncID)
		{
			if(m_audio and m_data)
			{
				Bytes message = FlowSyncManager::makeSyncMessage(syncID, 2);
				m_audio->write(message, INFINITY, INFINITY);
				m_data->write(message, INFINITY, INFINITY);
			}
		}

		std::shared_ptr<SendFlow> m_video;
		std::shared_ptr<SendFlow> m_audio;
		std::shared_ptr<SendFlow> m_data;
		std::set<std::shared_ptr<RecvFlow>> m_recvFlows;
	};

	void onSetPeerInfoCommand(const Args &args) override
	{
		Client::onSetPeerInfoCommand(args);

		m_setPeerInfoReceived = true;
		m_additionalAddresses.clear();

		auto addresses = AMF0::Array();

		for(size_t x = 3; x < args.size(); x++)
		{
			if(args[x]->isString())
			{
				Address each;
				each.setOrigin(Address::ORIGIN_REPORTED);
				if(each.setFromPresentation(args[x]->stringValue()))
				{
					m_additionalAddresses.push_back(each);
					addresses->appendValue(AMF0::String(each.toPresentation()));
				}
			}
		}

		clientLog("setPeerInfo", {{"addresses", addresses}});
	}

	bool setup(std::shared_ptr<RecvFlow> controlRecv)
	{
		m_controlRecv = controlRecv;
		m_controlSend = m_controlRecv->openReturnFlow(TCMetadata::encode(0, RO_SEQUENCE), PRI_IMMEDIATE);
		if(not m_controlSend)
			return false;

		m_farAddress = m_controlRecv->getFarAddress();
		m_farAddressStr = m_farAddress.toPresentation();

		m_controlSend->onException = [this] (uintmax_t reason) { close(); };
		m_controlSend->onRecvFlow = [this] (std::shared_ptr<RecvFlow> flow) { acceptOtherFlow(flow); };

		m_controlRecv->onComplete = [this] (bool error) { close(); };
		m_controlRecv->setSessionCongestionDelay(delaycc_delay);
		m_controlRecv->setSessionTrafficClass(dscp << 2);
		m_controlRecv->onFarAddressDidChange = [this] { onFarAddressDidChange(); };
		setOnMessage(m_controlRecv, 0, nullptr);

		rtmfpAcceptCount++;
		jsonLog("accept", {
			{"proto", AMF0::String("rtmfp")},
			{"address", AMF0::String(m_farAddressStr)},
			{"peerID", AMF0::String(Hex::encode(getPeerID(m_controlRecv)))}
		});

		m_controlRecv->accept();

		return true;
	}

	void acceptOtherFlow(std::shared_ptr<RecvFlow> flow)
	{
		uint32_t streamID = 0;
		ReceiveOrder rxOrder = RO_SEQUENCE;
		if(not TCMetadata::parse(flow->getMetadata(), &streamID, &rxOrder)) // only TC flows for now
			return;

		if(streamID and not m_netStreams.count(streamID))
			return; // reject if not for an active stream ID

		flow->setReceiveOrder(rxOrder);
		flow->setBufferCapacity((1<<24) - 1024); // 16MB, big enough for largest TCMessage

		std::shared_ptr<ReorderBuffer> reorderBuffer;
		if(RO_NETWORK == rxOrder)
			reorderBuffer = share_ref(new RunLoopReorderBuffer(&mainRL, reorderWindowPeriod), false);

		flow->onComplete = [this, flow, reorderBuffer, streamID] (bool error) {
			if(reorderBuffer)
				reorderBuffer->flush();
			m_netStreamTransports[streamID].m_recvFlows.erase(flow);
		};

		setOnMessage(flow, streamID, reorderBuffer);

		flow->accept();
		m_netStreamTransports[streamID].m_recvFlows.insert(flow);
	}

	void deliverMessage(uint32_t streamID, const uint8_t *bytes, size_t len)
	{
		uint8_t messageType = 0;
		uint32_t timestamp = 0;
		size_t rv = TCMessage::parseHeader(bytes, bytes + len, &messageType, &timestamp);
		if(rv)
			onMessage(streamID, messageType, timestamp, bytes + rv, len - rv);
	}

	bool shouldAlwaysDeliver(const uint8_t *bytes, size_t len)
	{
		uint8_t messageType = 0;
		size_t rv = TCMessage::parseHeader(bytes, bytes + len, &messageType, nullptr);
		if(not rv)
			return false;

		switch(messageType)
		{
		case TCMSG_VIDEO: return App::isVideoSequenceSpecial(bytes + rv, len - rv);
		case TCMSG_AUDIO: return Message::isAudioSequenceSpecial(bytes + rv, len - rv);
		default: return true;
		}
	}

	void setOnMessage(const std::shared_ptr<RecvFlow> &flow, uint32_t streamID, const std::shared_ptr<ReorderBuffer> &reorderBuffer)
	{
		if(reorderBuffer)
		{
			reorderBuffer->onMessage = [this, streamID] (const uint8_t *bytes, size_t len, uintmax_t sequenceNumber, size_t fragmentCount, bool isLate) {
				if((not isLate) or shouldAlwaysDeliver(bytes, len))
					deliverMessage(streamID, bytes, len);
				if(isLate and (verbose > 1))
					printf("message %lu late, %s\n", (unsigned long)sequenceNumber, shouldAlwaysDeliver(bytes, len) ? "relayed anyway" : "dropped");
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

	void onFarAddressDidChange()
	{
		Address oldAddress = m_farAddress;
		m_farAddress = m_controlRecv->getFarAddress();
		m_farAddressStr = m_farAddress.toPresentation();
		clientLog("address-change", {{"oldAddress", AMF0::String(oldAddress.toPresentation())}});
		write(0, TCMSG_COMMAND, 0, Message::command("onStatus", 0, nullptr,
			AMF0::Object()
				->putValueAtKey(AMF0::String("status"), "level")
				->putValueAtKey(AMF0::String("NetConnection.AddressChange.Notify"), "code")
			), INFINITY, INFINITY);
	}

	void syncAudioAndData(uint32_t streamID) override
	{
		if(streamID)
		{
			auto &stream = m_netStreamTransports[streamID];
			stream.syncAudioAndData(m_nextSyncID++);
		}
	}

	void deleteStreamTransport(uint32_t streamID) override
	{
		m_netStreamTransports.erase(streamID);
	}

	std::string protocol() const override { return "rtmfp"; }

	uint32_t m_nextSyncID { 0 };
	FlowSyncManager m_syncManager;
	std::shared_ptr<SendFlow> m_controlSend;
	std::shared_ptr<RecvFlow> m_controlRecv;
	std::map<uint32_t, NetStreamTransport> m_netStreamTransports;
	bool m_setPeerInfoReceived { false };
	std::vector<Address> m_additionalAddresses;
};

class RTMPClient : public Client {
public:
	static void newClient(int fd, bool simple, const Address &addr)
	{
		auto client = share_ref(new RTMPClient(simple), false);
		if(not client->setFd(fd))
			return;

		client->m_farAddress = addr;
		client->m_farAddressStr = client->m_farAddress.toPresentation();

		client->m_adapter->onShutdownCompleteCallback = [client] { client->onShutdownComplete(); };
		client->m_rtmp->onmessage = [client] (uint32_t streamID, uint8_t messageType, uint32_t timestamp, const uint8_t *payload, size_t len) {
			client->onMessage(streamID, messageType, timestamp, payload, len);
		};
		client->m_rtmp->onerror = [client] { client->close(); };

		clients[client->m_connectionID] = client;
		updateRedirectorLoadFactor();
	}

	RTMPClient(bool simple) : m_simple(simple)
	{
		m_adapter = share_ref(new PosixStreamPlatformAdapter(&mainRL), false);
		m_rtmp = share_ref(new RTMP(m_adapter), false);
		m_rtmp->init(true);

		if(simple)
		{
			m_rtmp->setSimpleMode(true);
			m_rtmp->setChunkSize(1<<24); // maximum message size
		}

		setRandomConnectionID();
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

		return true;
	}

	void close() override
	{
		Client::close();

		m_rtmp->close();
		m_rtmp->onmessage = nullptr;
		m_rtmp->onerror = nullptr;
		m_rtmp->onopen = nullptr;
	}

	std::shared_ptr<WriteReceipt> write(uint32_t streamID, uint8_t messageType, uint32_t timestamp, const void *payload, size_t len, Time startWithin, Time finishWithin) override
	{
		Priority pri = PRI_ROUTINE;
		switch(messageType)
		{
		case TCMSG_COMMAND:
		case TCMSG_COMMAND_EX:
		case TCMSG_DATA:
		case TCMSG_DATA_EX:
		case TCMSG_USER_CONTROL:
			// think about cases for different priority for these
		case TCMSG_AUDIO:
			pri = PRI_IMMEDIATE;
			break;
		case TCMSG_VIDEO:
			pri = PRI_PRIORITY;
			break;
		}

		return m_rtmp->write(pri, streamID, messageType, timestamp, payload, len, startWithin, finishWithin);
	}

protected:
	std::string protocol() const override { return m_simple ? "rtmp-simple" : "rtmp"; }

	std::shared_ptr<PosixStreamPlatformAdapter> m_adapter;
	std::shared_ptr<RTMP> m_rtmp;
	bool m_simple;
};

class RTWebSocketClient : public Client {
// Almost, but not entirely, just like RTMFPClient.
public:
	static void newClient(int fd, const Address &addr)
	{
		auto client = share_ref(new RTWebSocketClient(), false);

		client->setRandomConnectionID();
		client->m_farAddress = addr;
		client->m_farAddressStr = client->m_farAddress.toPresentation();

		// RTWebSocket is expected to mostly be used with a reverse proxy, which decreases the
		// potential effectiveness of TCP_NOTSENT_LOWAT. Allow bigger writes per select since
		// it won't make a big difference for real-time responsiveness through proxied connections.
		client->m_platformStream = share_ref(new PosixStreamPlatformAdapter(&mainRL, 4096, 8192), false);
		client->m_platformStream->onShutdownCompleteCallback = [client] { client->onShutdownComplete(); };

		int tos = dscp << 2;
		setsockopt(fd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos));
		setsockopt(fd, IPPROTO_IPV6, IPV6_TCLASS, &tos, sizeof(tos));

		if(not client->m_platformStream->setSocketFd(fd))
		{
			::close(fd);
			return;
		}

		client->m_wsMessageAdapter = share_ref(new rtws::SimpleWebSocketMessagePlatformAdapter(client->m_platformStream), false);
		client->m_websock = share_ref(new SimpleWebSocket_OpenSSL(client->m_platformStream), false);
		client->m_websock->onHttpHeadersReceived = [client] { client->onHttpHeadersReceived(); };
		client->m_wsMessageAdapter->init(client->m_websock);
		client->m_rtws = share_ref(new rtws::RTWebSocket(client->m_wsMessageAdapter), false);

		client->m_wsMessageAdapter->onOpen = [client] { client->m_rtws->init(); };
		client->m_rtws->onRecvFlow = [client] (std::shared_ptr<rtws::RecvFlow> flow) { client->acceptControlFlow(flow); };
		client->m_rtws->onError = [client] { client->close(); };
		client->m_rtws->maxAdditionalDelay = (delaycc_delay < INFINITY) ? delaycc_delay : 0.25; // TODO tune default
		client->m_rtws->minOutstandingThresh = 16 * 1024; // default is 64KB, probably too big

		clients[client->m_connectionID] = client;
		updateRedirectorLoadFactor();
	}

	void close() override
	{
		if(not m_open)
			return;

		Client::close();
		m_netStreamTransports.clear(); // closes all NetStream flows
		if(m_rtws)
			m_rtws->close(); // closes everything
		if(m_platformStream)
			m_platformStream->close();
		onShutdownComplete();
	}

	std::shared_ptr<WriteReceipt> write(uint32_t streamID, uint8_t messageType, uint32_t timestamp, const void *payload, size_t len, Time startWithin, Time finishWithin) override
	{
		if(0 == streamID)
			return m_controlSend->write(TCMessage::message(messageType, timestamp, (const uint8_t *)payload, len), startWithin, finishWithin);

		auto &stream = m_netStreamTransports[streamID]; // create on demand
		return stream.write(m_controlRecv, streamID, messageType, timestamp, (const uint8_t *)payload, len, startWithin, finishWithin);
	}

protected:
	struct NetStreamTransport {
		~NetStreamTransport()
		{
			if(m_video) m_video->close();
			if(m_audio) m_audio->close();
			if(m_data) m_data->close();

			for(auto it = m_recvFlows.begin(); it != m_recvFlows.end(); it++)
				(*it)->close();
		}

		rtws::SendFlow * openFlowForType(const std::shared_ptr<rtws::RecvFlow> &control, uint32_t streamID, uint8_t messageType)
		{
			Priority pri = PRI_IMMEDIATE;
			ReceiveOrder rxIntent = RO_SEQUENCE;
			std::shared_ptr<rtws::SendFlow> *flowRef = &m_data;

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

		std::shared_ptr<WriteReceipt> write(const std::shared_ptr<rtws::RecvFlow> &control, uint32_t streamID, uint8_t messageType, uint32_t timestamp, const uint8_t *payload, size_t len, Time startWithin, Time finishWithin)
		{
			rtws::SendFlow *flow = openFlowForType(control, streamID, messageType);
			if(not flow)
				return nullptr;
			return flow->write(TCMessage::message(messageType, timestamp, payload, len), startWithin, finishWithin);
		}

		void syncAudioAndData(uint32_t syncID)
		{
			if(m_audio and m_data)
			{
				Bytes message = FlowSyncManager::makeSyncMessage(syncID, 2);
				m_audio->write(message, INFINITY, INFINITY);
				m_data->write(message, INFINITY, INFINITY);
			}
		}

		std::shared_ptr<rtws::SendFlow> m_video;
		std::shared_ptr<rtws::SendFlow> m_audio;
		std::shared_ptr<rtws::SendFlow> m_data;
		std::set<std::shared_ptr<rtws::RecvFlow>> m_recvFlows;
	};

	void onHttpHeadersReceived()
	{
		auto forwardedFor = m_websock->getHeader("x-forwarded-for");
		if(not forwardedFor.empty())
			m_farAddressStr = m_farAddress.toPresentation() + ";" + forwardedFor;
	}

	void acceptControlFlow(std::shared_ptr<rtws::RecvFlow> flow)
	{
		uint32_t streamID = 0;
		if(m_controlRecv or (not TCMetadata::parse(flow->getMetadata(), &streamID, nullptr)) or (0 != streamID))
			return;

		m_controlRecv = flow;
		m_controlSend = m_controlRecv->openReturnFlow(TCMetadata::encode(0, RO_SEQUENCE), PRI_IMMEDIATE);
		if(not m_controlSend)
			return;

		m_controlSend->onException = [this] (uintmax_t reason, const std::string &description) { close(); };
		m_controlSend->onRecvFlow = [this] (std::shared_ptr<rtws::RecvFlow> flow) { acceptOtherFlow(flow); };

		m_controlRecv->onComplete = [this] { close(); };
		setOnMessage(m_controlRecv, 0);

		m_controlRecv->accept();

		clientLog("accept-control", {});
	}

	void acceptOtherFlow(std::shared_ptr<rtws::RecvFlow> flow)
	{
		uint32_t streamID = 0;
		if(not TCMetadata::parse(flow->getMetadata(), &streamID, nullptr)) // only TC flows for now
			return;

		if(streamID and not m_netStreams.count(streamID))
			return; // reject if not for an active stream ID

		flow->setBufferCapacity((1<<24) - 1); // 16MB, big enough for largest TCMessage

		flow->onComplete = [this, flow, streamID] {
			m_netStreamTransports[streamID].m_recvFlows.erase(flow);
		};

		setOnMessage(flow, streamID);

		flow->accept();
		m_netStreamTransports[streamID].m_recvFlows.insert(flow);
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
			if(rv)
				onMessage(streamID, messageType, timestamp, bytes + rv, len - rv);
		};
	}

	void syncAudioAndData(uint32_t streamID) override
	{
		if(streamID)
		{
			auto &stream = m_netStreamTransports[streamID];
			stream.syncAudioAndData(m_nextSyncID++);
		}
	}

	void deleteStreamTransport(uint32_t streamID) override
	{
		m_netStreamTransports.erase(streamID);
	}

	std::string protocol() const override { return "rtws"; }

	uint32_t m_nextSyncID { 0 };
	std::shared_ptr<rtws::SendFlow> m_controlSend;
	std::shared_ptr<rtws::RecvFlow> m_controlRecv;
	std::map<uint32_t, NetStreamTransport> m_netStreamTransports;

	std::shared_ptr<rtws::RTWebSocket> m_rtws;
	std::shared_ptr<SimpleWebSocket> m_websock;
	std::shared_ptr<rtws::SimpleWebSocketMessagePlatformAdapter> m_wsMessageAdapter;
	std::shared_ptr<PosixStreamPlatformAdapter> m_platformStream;
};

// --- App

std::shared_ptr<App> App::getApp(const std::string &name)
{
	auto it = apps.find(name);
	if(it != apps.end())
		return it->second;

	std::shared_ptr<App> rv = share_ref(new App(name), false);
	apps[name] = rv;

	return rv;
}

void App::addClient(std::shared_ptr<Client> client, const std::string &username, bool isExclusive)
{
	// insert new client first so we don't destroy the app when closing
	// a duplicate exclusive username
	m_clients.insert(client);
	m_connectCount++;
	m_maxClients = std::max(m_maxClients, m_clients.size());

	if(isExclusive)
	{
		auto it = m_exclusiveClients.find(username);
		if(it != m_exclusiveClients.end())
			it->second->close();

		m_exclusiveClients[username] = client;
	}
}

void App::removeClient(std::shared_ptr<Client> client, const std::string &username)
{
	m_exclusiveClients.erase(username);
	m_clients.erase(client);
	if(m_clients.empty())
		apps.erase(m_name);
}

void App::broadcastMessage(Client *sender, const Bytes &message)
{
	m_broadcastCount++;
	for(auto it = m_clients.begin(); it != m_clients.end(); it++)
		(*it)->sendRelay(sender, message);
}

void App::sendShutdownNotify()
{
	for(auto it = m_clients.begin(); it != m_clients.end(); it++)
		(*it)->sendShutdownNotify();
}

void App::subscribeStream(const std::string &hashname, std::shared_ptr<NetStream> netStream)
{
	auto &stream = m_streams[hashname];
	stream.m_subscribers.insert(netStream);
	if(stream.m_publishing)
		netStream->m_owner->sendPublishNotify(netStream, stream);
	currentSubscribeCount++;
	subscribeCount++;
	m_subscribeCount++;
}

void App::unsubscribeStream(const std::string &hashname, std::shared_ptr<NetStream> netStream)
{
	auto &stream = m_streams[hashname];
	stream.m_subscribers.erase(netStream);
	cleanupStream(hashname);
	currentSubscribeCount--;
}

bool App::publishStream(const std::string &hashname, std::shared_ptr<NetStream> netStream, double publishPriority)
{
	auto &stream = m_streams[hashname];
	if(stream.m_publishing)
	{
		if(publishPriority > stream.m_priority)
		{
			releaseStream(hashname, publishPriority);
			return publishStream(hashname, netStream, publishPriority);
		}

		return false;
	}
	stream.m_publishing = true;
	stream.m_publisher = netStream;
	stream.m_priority = publishPriority;

	for(auto it = stream.m_subscribers.begin(); it != stream.m_subscribers.end(); it++)
		(*it)->m_owner->sendPublishNotify(*it, stream);

	currentPublishCount++;
	publishCount++;
	m_publishCount++;

	return true;
}

void App::unpublishStream(const std::string &hashname)
{
	auto &stream = m_streams[hashname];
	stream.unpublishClear();

	for(auto it = stream.m_subscribers.begin(); it != stream.m_subscribers.end(); it++)
		(*it)->m_owner->sendUnpublishNotify(*it);

	cleanupStream(hashname);
	currentPublishCount--;
}

void App::releaseStream(const std::string &hashname, double publishPriority)
{
	auto it = m_streams.find(hashname);
	if(it == m_streams.end())
		return;

	auto &stream = it->second;
	if(stream.m_publisher and (publishPriority > stream.m_priority))
		stream.m_publisher->m_owner->releaseStream(stream.m_publisher);
}

void App::cleanupStream(const std::string &hashname)
{
	auto &stream = m_streams[hashname];
	if(stream.m_subscribers.empty() and not stream.m_publishing)
	{
		if(verbose > 1) printf("no publishers and no subscribers for stream %s, erasing\n", hashname.c_str());
		m_streams.erase(hashname);
	}
}

void App::onStreamMessage(const std::string &hashname, uint8_t messageType, uint32_t timestamp, const uint8_t *payload, size_t len)
{
	const uint8_t *actualPayload = payload;
	const uint8_t *limit = payload + len;

	auto &stream = m_streams[hashname];

	if(TCMSG_DATA == messageType)
	{
		if(verbose > 1)
		{
			Args args;
			if(not AMF0::decode(payload, limit, args))
				Hex::print("can't fully decode AMF0", payload, limit);
			for(auto it = args.begin(); it != args.end(); it++)
				printf("  %s\n", (*it)->repr().c_str());
		}
		const uint8_t *cursor = payload;

		auto commandName = AMF0::decode(&cursor, limit);
		const uint8_t *cursorAtCallbackName = cursor;
		auto callbackName = AMF0::decode(&cursor, limit); // might not be present
		if(commandName and callbackName and commandName->isString() and callbackName->isString())
		{
			if(0 == strcmp(commandName->stringValue(), "@setDataFrame"))
			{
				stream.m_dataFrames[callbackName->stringValue()] = Bytes(cursorAtCallbackName, limit); // so we don't have to reserialize for new subscribers
				actualPayload = cursorAtCallbackName;
				if(verbose) jsonLog("@setDataFrame", {{"app", AMF0::String(m_name)}, {"hashname", AMF0::String(hashname)}, {"callbackName", callbackName}});
			}
			else if(0 == strcmp(commandName->stringValue(), "@clearDataFrame"))
			{
				stream.m_dataFrames.erase(callbackName->stringValue());
				if(verbose) jsonLog("@clearDataFrame", {{"app", AMF0::String(m_name)}, {"hashname", AMF0::String(hashname)}, {"callbackName", callbackName}});
				return; // does not need to be forwarded
			}
		}
	}
	else if(TCMSG_VIDEO == messageType)
	{
		if(len) // don't count video silence messages
		{
			uint32_t codec = Message::getVideoCodec(payload, len);

			if((codec != stream.m_lastVideoCodec) and (TC_VIDEO_CODEC_NONE != codec))
			{
				stream.m_videoInit.clear();
				stream.m_lastVideoKeyframe.clear();
				stream.m_videoMetadataBeforeInit.clear();
				stream.m_videoMetadataLatest.clear();
				stream.m_lastVideoCodec = codec;
			}
		}

		if(Message::isVideoInit(payload, len))
		{
			stream.m_videoInit = Bytes(payload, payload + len);
			stream.m_lastVideoKeyframe.clear();
			if(not stream.m_videoMetadataLatest.empty())
			{
				stream.m_videoMetadataBeforeInit = stream.m_videoMetadataLatest;
				stream.m_videoMetadataLatest.clear();
			}
		}
		else if(Message::isVideoEnhancedMetadata(payload, len))
		{
			stream.m_videoMetadataLatest = Bytes(payload, payload + len);
			stream.m_lastVideoKeyframe.clear();
		}
		else if(Message::isVideoKeyframe(payload, len))
		{
			stream.m_lastVideoKeyframe = Bytes(payload, payload + len);
			stream.m_lastVideoFrameWasKey = true;
		}
		else
			stream.m_lastVideoFrameWasKey = false;

		stream.m_lastVideoTimestamp = timestamp;
	}
	else if(TCMSG_AUDIO == messageType)
	{
		if(len) // don't count silence messages
		{
			uint32_t codec = Message::getAudioCodec(payload, len);
			if(codec != stream.m_lastAudioCodec)
			{
				stream.m_audioInit.clear();
				stream.m_lastAudioCodec = codec;
				stream.m_audioMultichannelConfigBeforeInit.clear();
				stream.m_audioMultichannelConfigLatest.clear();
			}
		}

		if(Message::isAudioInit(payload, len))
		{
			stream.m_audioInit = Bytes(payload, payload + len);
			if(not stream.m_audioMultichannelConfigLatest.empty())
			{
				stream.m_audioMultichannelConfigBeforeInit = stream.m_audioMultichannelConfigLatest;
				stream.m_audioMultichannelConfigLatest.clear();
			}
		}
		else if(Message::isAudioEnhancedMultichannelConfig(payload, len))
			stream.m_audioMultichannelConfigLatest = Bytes(payload, payload + len);
	}

	for(auto it = stream.m_subscribers.begin(); it != stream.m_subscribers.end(); it++)
		(*it)->m_owner->relayStreamMessage(*it, messageType, timestamp, actualPayload, limit - actualPayload);
}

bool App::isVideoCheckpointCommand(const uint8_t *payload, size_t len)
{
	if(len < 2)
		return false;
	if(TC_VIDEO_FRAMETYPE_COMMAND != (payload[0] & TC_VIDEO_FRAMETYPE_MASK))
		return false;
	if(Message::isVideoEnhanced(payload, len))
	{
		if(len < 6)
			return false;
		return TC_VIDEO_COMMAND_RANDOM_ACCESS_CHECKPOINT == payload[5];
	}
	else if(TC_VIDEO_CODEC_AVC == Message::getVideoCodec(payload, len))
	{
		if(len < 6)
			return false;
		return TC_VIDEO_COMMAND_RANDOM_ACCESS_CHECKPOINT == payload[5];
	}
	else
		return TC_VIDEO_COMMAND_RANDOM_ACCESS_CHECKPOINT == payload[1];
}

bool App::isVideoSequenceSpecial(const uint8_t *payload, size_t len)
{
	if(isVideoCheckpointCommand(payload, len))
		return false;
	return Message::isVideoSequenceSpecial(payload, len);
}

// ---

void signal_handler(int param)
{
	interrupted = true;
}

void stats_signal_handler(int param)
{
	showStats = true;
}

void unregister_signal_handler(int param)
{
	unregister = true;
}

void printStats()
{
	showStats = false;
	jsonLog("stats", {
		{"clients", AMF0::Number(clients.size())},
		{"apps", AMF0::Number(apps.size())},
		{"publishing", AMF0::Number(currentPublishCount)},
		{"playing", AMF0::Number(currentSubscribeCount)},
		{"connects", AMF0::Number(connectCount)},
		{"publishes", AMF0::Number(publishCount)},
		{"plays", AMF0::Number(subscribeCount)},
		{"broadcasts", AMF0::Number(broadcastCount)},
		{"relaysIn", AMF0::Number(relaysIn)},
		{"relaysOut", AMF0::Number(relaysOut)},
		{"accepts", share_ref(AMF0::Object()
			->putValueAtKey(AMF0::Number(rtmfpAcceptCount), "rtmfp")
			->putValueAtKey(AMF0::Number(rtmpAcceptCount), "rtmp")
			->putValueAtKey(AMF0::Number(rtwsAcceptCount), "rtws")
			->putValueAtKey(AMF0::Number(rtmfpAcceptCount + rtmpAcceptCount + rtwsAcceptCount), "@all")
		)},
		{"lookups", AMF0::Number(lookupCount)},
		{"intros", AMF0::Number(introCount)},
		{"publishedDuration", AMF0::Number(::round(publishedDuration))},
		{"playedDuration", AMF0::Number(::round(playedDuration))}
	});
	fflush(stdout);
}

bool listenTCP(const Address &addr, Protocol protocol, std::vector<int> &listenFds)
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

	union Address::in_sockaddr boundAddr;
	socklen_t addrLen = sizeof(boundAddr);
	getsockname(fd, &boundAddr.s, &addrLen);
	jsonLog("listen", {{"proto", AMF0::String(protocolDescription(protocol))}, {"bind", AMF0::String(Address(&boundAddr.s).toPresentation())}});

	if(listen(fd, 5))
	{
		::perror("listen");
		return false;
	}

	mainRL.registerDescriptor(fd, RunLoop::READABLE, [protocol] (RunLoop *sender, int fd, RunLoop::Condition cond) {
		Address::in_sockaddr boundAddr_u;
		socklen_t addrLen = sizeof(Address::in_sockaddr);
		int newFd = accept(fd, &boundAddr_u.s, &addrLen);
		if(newFd < 0)
		{
			::perror("accept");
			return;
		}

		int optval = 1;
		int optlen = sizeof(optval);
		setsockopt(newFd, SOL_SOCKET, SO_KEEPALIVE, &optval, optlen);

#ifdef TCP_KEEPALIVE
		optval = 30;
		setsockopt(newFd, IPPROTO_TCP, TCP_KEEPALIVE, &optval, optlen);
#endif

#ifdef TCP_KEEPIDLE
		optval = 30;
		setsockopt(newFd, IPPROTO_TCP, TCP_KEEPIDLE, &optval, optlen);
#endif

#ifdef TCP_KEEPINTVL
		optval = 30;
		setsockopt(newFd, IPPROTO_TCP, TCP_KEEPINTVL, &optval, optlen);
#endif

		Address boundAddr(&boundAddr_u.s);
		jsonLog("accept", {{"address", AMF0::String(boundAddr.toPresentation())}, {"proto", AMF0::String(protocolDescription(protocol))}});

		switch(protocol)
		{
		case PROTO_RTMP:
			RTMPClient::newClient(newFd, false, boundAddr);
			rtmpAcceptCount++;
			break;

		case PROTO_RTMP_SIMPLE:
			RTMPClient::newClient(newFd, true, boundAddr);
			rtmpAcceptCount++;
			break;

		case PROTO_RTWS:
			RTWebSocketClient::newClient(newFd, boundAddr);
			rtwsAcceptCount++;
			break;

		default:
			::close(newFd);
			break;
		}
	});

	listenFds.push_back(fd);

	return true;
}

void unregisterAndCloseFds(std::vector<int> &fds)
{
	for(auto it = fds.begin(); it != fds.end(); it++)
	{
		mainRL.unregisterDescriptor(*it);
		::close(*it);
	}
	fds.clear();
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

	printf("usage: %s (-B|-b|-s|-w addr:port)... [options] -- server\n", prog);
	printf("usage: %s (-k|-K key) app...                   -- auth token generator\n", prog);
	printf("  -B addr:port  -- listen for rtmfp on UDP addr:port\n");
	printf("  -b addr:port  -- listen for rtmp on TCP addr:port\n");
	printf("  -s addr:port  -- listen for rtmp-simple on TCP addr:port\n");
	printf("  -w addr:port  -- listen for RTWebSocket on TCP addr:port\n");
	printf("  -i string     -- set connect serverInfo (%s%s)\n", serverInfo ? "default " : "unset", serverInfo ? serverInfo : "");
	printf("  -V sec        -- video queue lifetime (default %.3Lf)\n", videoLifetime);
	printf("  -A sec        -- audio queue lifetime (default %.3Lf)\n", audioLifetime);
	printf("  -F sec        -- finish-by margin (default %.3Lf)\n", finishByMargin);
	printf("  -e sec        -- expire previous GOP start-by margin (default %.3Lf)\n", previousGopStartByMargin);
	printf("  -r sec        -- reorder window duration (rtmfp receive, default %.3Lf)\n", reorderWindowPeriod);
	printf("  -E            -- don't expire previous GOP\n");
	printf("  -C sec        -- checkpoint queue lifetime (default %.3Lf)\n", checkpointLifetime);
	printf("  -T DSCP|name  -- set DiffServ field on outgoing packets (default %d)\n", dscp);
	printf("  -X sec        -- set congestion extra delay threshold (rtmfp, rtws, default %.3Lf)\n", delaycc_delay);
	printf("  -x            -- use static Diffie-Hellman keys instead of ephemeral (rtmfp)\n");
	printf("  -H            -- don't require HMAC (rtmfp)\n");
	printf("  -S            -- don't require session sequence numbers (rtmfp)\n");
	printf("  -m            -- allow multiple connections per session (rtmfp)\n");
	printf("  -k key-text   -- add auth secret (text)\n");
	printf("  -K key-hex    -- add auth secret (binary hex)\n");
	printf("  -L redir-spec -- add redirector/LB spec <name>@<ip:port>[,ip:port...]\n");
	printf("  -l user:passw -- add redirector username:password\n");
	printf("  -d addr:port  -- advertise addr:port at redirector\n");
	printf("  -D            -- suppress redirector advertising reflexive (derived) address\n");
	printf("  -t sec        -- shutdown deadline on SIGTERM (default %.3Lf)\n", gracefulShutdownTimeout);
	printf("  -c            -- allow new connections while shutting down\n");
	printf("  -v            -- increase verbose output\n");
	printf("  -h            -- show this help\n");
	printf("\n");
	printf("signals:\n");
	printf("  SIGINT  -- shut down now\n");
	printf("  SIGTERM -- unregister from redirectors, shut down when idle or deadline\n");
#if defined(SIGINFO) && !defined(__linux__)
	printf("  SIGINFO -- print stats\n");
#endif
	printf("  SIGUSR1 -- print stats\n");
	return rv;
}

}

int main(int argc, char **argv)
{
	std::vector<Address> rtmfpAddrs;
	std::vector<Address> rtmpAddrs;
	std::vector<Address> rtmpSimpleAddrs;
	std::vector<Address> rtwsAddrs;
	int ch;
	bool advertiseReflexive = true;
	bool ephemeralDH = true;
	std::map<std::string, std::string> redirectAuth;
	std::map<std::string, std::vector<Address>> redirectorSpecs;
	std::vector<Address> advertiseAddresses;

	pid = getpid();

	while((ch = getopt(argc, argv, "V:A:F:e:r:EC:T:X:xHSB:b:s:w:i:mk:K:L:l:d:Dt:cvh")) != -1)
	{
		switch(ch)
		{
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
		case 'r':
			reorderWindowPeriod = atof(optarg);
			break;
		case 'E':
			expirePreviousGop = false;
			break;
		case 'C':
			checkpointLifetime = atof(optarg);
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
		case 'x':
			ephemeralDH = false;
			break;
		case 'H':
			requireHMAC = false;
			break;
		case 'S':
			requireSSEQ = false;
			break;
		case 'B':
			if(not appendAddress(optarg, rtmfpAddrs))
				return usage(argv[0], 1, "(-B) can't parse bind address: ", optarg);
			break;
		case 'b':
			if(not appendAddress(optarg, rtmpAddrs))
				return usage(argv[0], 1, "(-b) can't parse bind address: ", optarg);
			break;
		case 's':
			if(not appendAddress(optarg, rtmpSimpleAddrs))
				return usage(argv[0], 1, "(-s) can't parse bind address: ", optarg);
			break;
		case 'w':
			if(not appendAddress(optarg, rtwsAddrs))
				return usage(argv[0], 1, "(-w) can't parse bind address: ", optarg);
			break;
		case 'i':
			serverInfo = optarg;
			break;
		case 'm':
			allowMultipleConnections = true;
			break;
		case 'k':
			secrets.push_back(Bytes(optarg, optarg + strlen(optarg)));
			memset(optarg, '#', strlen(optarg));
			break;
		case 'K':
			{
				Bytes key;
				if(not Hex::decode(optarg, key))
					return usage(argv[0], 1, "-K can't parse hex key: ", optarg);
				secrets.push_back(key);
				memset(optarg, '#', strlen(optarg));
			}
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
		case 't':
			gracefulShutdownTimeout = atof(optarg);
			break;
		case 'c':
			allowConnectDuringShutdown = true;
			break;
		case 'v':
			verbose++;
			break;

		case 'h':
		default:
			return usage(argv[0], 'h' != ch);
		}
	}

	if(argc > optind)
	{
		if(secrets.size() != 1)
			return usage(argv[0], 1, "specify exactly one key for auth token generation", nullptr);

		FlashCryptoAdapter_OpenSSL crypto;
		flashcrypto = &crypto;

		for(; optind < argc; optind++)
			printf("%s\n", AMF0::Object()
				->putValueAtKey(AMF0::String("auth"), "@type")
				->putValueAtKey(AMF0::String(argv[optind]), "app")
				->putValueAtKey(AMF0::String(hexHMACSHA256(secrets[0], argv[optind])), "token")
				->toJSON(0).c_str()
			);

		return 0;
	}

	if(0 == rtmfpAddrs.size() + rtmpAddrs.size() + rtmpSimpleAddrs.size() + rtwsAddrs.size())
		return usage(argv[0], 1, "specify at least one listen address");
	if(redirectorSpecs.size() and rtmfpAddrs.empty())
		return usage(argv[0], 1, "redirectors specified but not listening for rtmfp");

	FlashCryptoAdapter_OpenSSL crypto;
	if(not crypto.init(true, ephemeralDH, nullptr))
	{
		printf("crypto.init error\n");
		return 1;
	}
	crypto.setHMACSendAlways(requireHMAC);
	crypto.setHMACRecvRequired(requireHMAC);
	crypto.setSSeqSendAlways(requireSSEQ);
	crypto.setSSeqRecvRequired(requireSSEQ);
	flashcrypto = &crypto;

	serverId = std::string(Hex::encode(crypto.getFingerprint()), 0, 10);

	PerformerPosixPlatformAdapter platform(&mainRL, &mainPerformer, &workerPerformer);

	bool rtmfpShutdownComplete = false;
	platform.onShutdownCompleteCallback = [&rtmfpShutdownComplete] { rtmfpShutdownComplete = true; };

	RTMFP rtmfp(&platform, &crypto);
	platform.setRtmfp(&rtmfp);

	rtmfp.setDefaultSessionKeepalivePeriod(10);
	rtmfp.setDefaultSessionRetransmitLimit(20);
	rtmfp.setDefaultSessionIdleLimit(120);

	jsonLog("rtmfp", {{"fingerprint", AMF0::String(Hex::encode(crypto.getFingerprint()))}});

	for(auto it = rtmfpAddrs.begin(); it != rtmfpAddrs.end(); it++)
	{
		auto boundAddr = platform.addUdpInterface(it->getSockaddr());
		if(not boundAddr)
		{
			printf("rtmfp can't bind to requested address: %s\n", it->toPresentation().c_str());
			return 1;
		}
		jsonLog("listen", {{"proto", AMF0::String("rtmfp")}, {"bind", AMF0::String(boundAddr->toPresentation())}});
	}

	rtmfp.onRecvFlow = RTMFPClient::newClient;
	rtmfp.onUnmatchedIHello = [&rtmfp] (const void *epd, size_t epdLen, const void *tag, size_t tagLen, int interfaceID, const struct sockaddr *srcAddr) {
		Client::onUnmatchedIHello(&rtmfp, epd, epdLen, tag, tagLen, interfaceID, srcAddr);
	};

	for(auto it = redirectorSpecs.begin(); it != redirectorSpecs.end(); it++)
	{
		auto hostname = it->first;
		Bytes epd = crypto.makeEPD(nullptr, nullptr, hostname.c_str());
		auto redirectorClient = share_ref(new FlashCryptoRunLoopRedirectorClient(&rtmfp, epd, &mainRL, &crypto), false);
		redirectors.push_back(redirectorClient);
		auto redirectorClient_ptr = redirectorClient.get();
		config_redirector_client(redirectorClient_ptr, redirectAuth, it->second, advertiseAddresses, advertiseReflexive);

		redirectorClient->setLoadFactorUpdateInterval(1);

		redirectorClient->onReflexiveAddress = [hostname, redirectorClient_ptr] (const Address &addr) {
			jsonLog("redirector-reflexive", {
				{"redirector", AMF0::String(hostname)},
				{"address", AMF0::String(redirectorClient_ptr->getRedirectorAddress().toPresentation())},
				{"reflexiveAddress", AMF0::String(addr.toPresentation())}
			});
		};
		redirectorClient->onStatus = [hostname, redirectorClient_ptr] (RedirectorClient::Status status) {
			jsonLog("redirector-status", {
				{"redirector", AMF0::String(hostname)},
				{"address", AMF0::String(redirectorClient_ptr->getRedirectorAddress().toPresentation())},
				{"status", AMF0::String(redirectorStatusDescription(status))}
			});
		};

		redirectorClient->connect();
	}

	std::vector<int> listenFds;

	for(auto it = rtmpAddrs.begin(); it != rtmpAddrs.end(); it++)
		if(not listenTCP(*it, PROTO_RTMP, listenFds))
			return 1;

	for(auto it = rtmpSimpleAddrs.begin(); it != rtmpSimpleAddrs.end(); it++)
		if(not listenTCP(*it, PROTO_RTMP_SIMPLE, listenFds))
			return 1;

	for(auto it = rtwsAddrs.begin(); it != rtwsAddrs.end(); it++)
		if(not listenTCP(*it, PROTO_RTWS, listenFds))
			return 1;

	::signal(SIGINT, signal_handler);
	::signal(SIGTERM, unregister_signal_handler);

	::signal(SIGUSR1, stats_signal_handler);
#if defined(SIGINFO) && !defined(__linux__)
	::signal(SIGINFO, stats_signal_handler); // not POSIX, very common but not on Linux
#endif

	mainRL.onEveryCycle = [&rtmfp, &rtmfpShutdownComplete, &listenFds] {
		if(unregister and shuttingDown)
			interrupted = true;

		if(interrupted)
		{
			interrupted = false;
			jsonLog("interrupted", {{"shutdown", AMF0::Boolean(stopping)}});
			if(stopping)
			{
				// failsafe
				clients.clear();
				rtmfpShutdownComplete = true;
			}
			else
				mainRL.scheduleRel(Timer::makeAction([] { interrupted = true; }), shutdownTimeout);

			stopping = true;

			auto safeClients = clients;
			for(auto it = safeClients.begin(); it != safeClients.end(); it++)
				it->second->close();

			unregisterAndCloseFds(listenFds);

			for(auto it = redirectors.begin(); it != redirectors.end(); it++)
				(*it)->close();

			rtmfp.shutdown(true);
			fflush(stdout);
		}

		if(showStats)
			printStats();

		if(unregister)
		{
			unregister = false;
			if(not shuttingDown)
			{
				shuttingDown = true;
				for(auto it = redirectors.begin(); it != redirectors.end(); it++)
					(*it)->setActive(false);
				for(auto it = apps.begin(); it != apps.end(); it++)
					it->second->sendShutdownNotify();
				if(not allowConnectDuringShutdown)
					unregisterAndCloseFds(listenFds);
				mainRL.scheduleRel(Timer::makeAction([] { interrupted = true; }), gracefulShutdownTimeout);
				jsonLog("unregister", {{"timeout", AMF0::Number(gracefulShutdownTimeout)}});
			}
		}

		if(shuttingDown and clients.empty())
			mainRL.doLater([] { interrupted = true; shuttingDown = false; });

		if(stopping and clients.empty() and rtmfpShutdownComplete)
			mainRL.stop();
	};

	mainRL.scheduleRel(Timer::makeAction([] { fflush(stdout); }), 0, 5);
	mainRL.scheduleRel(Timer::makeAction([] { showStats = true; }), 300, 300);

	auto workerThread = std::thread([] { workerRL.run(); });

	jsonLog("run", {});
	mainRL.run();

	workerPerformer.perform([] { workerRL.stop(); });
	workerThread.join();

	mainPerformer.close();
	workerPerformer.close();

	printStats();
	jsonLog("end", {});

	return 0;
}
