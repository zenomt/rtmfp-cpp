// Copyright © 2022 Michael Thornburgh
// SPDX-License-Identifier: MIT

// TC Server, a simple live media server for RTMFP/RTMP “Tin-Can” clients.
// See the help message and tcserver.md for more information.

// TODO: app and client constraints
// TODO: epoll RunLoop for Linux
// TODO: stats

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
#include <unistd.h>
#include <netinet/tcp.h>
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

using Args = std::vector<std::shared_ptr<AMF0>>;

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
Time checkpointLifetime = 4.5;
Time reorderWindowPeriod = 1.0;
Time delaycc_delay = INFINITY;
Time shutdownTimeout = 300.0;
bool expirePreviousGop = true;
bool allowMultipleConnections = false;
bool interrupted = false;
bool stopping = false;
int dscp = 0;
size_t maxNetStreamsPerClient = 256; // arbitrary
uint32_t timestampAdjustmentMargin = 4000;
std::vector<Bytes> secrets;

PreferredRunLoop mainRL;
Performer mainPerformer(&mainRL);
PreferredRunLoop workerRL;
Performer workerPerformer(&workerRL);
FlashCryptoAdapter *flashcrypto = nullptr; // set in main()

class Client;
std::map<Bytes, std::shared_ptr<Client>> clients;

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

std::string hexHMACSHA256(const Bytes &key, const std::string &app)
{
	uint8_t md[32] = { 0 };
	flashcrypto->hmacSHA256(md, key.data(), key.size(), app.data(), app.size());
	return Hex::encode(md, sizeof(md));
}

bool timestamp_lt(uint32_t l, uint32_t r)
{
	return (l - r) >= UINT32_C(0x80000000);
}

bool timestamp_gt(uint32_t l, uint32_t r)
{
	return timestamp_lt(r, l);
}

std::string logEscape(std::string s)
{
	static char xdigits[] = "0123456789abcdef";
	size_t len = s.size();
	const uint8_t *data = (const uint8_t *)s.data();

	std::string rv;
	while(len--)
	{
		uint8_t c = *data++;
		if((c < 32) or ('\\' == c) or (',' == c) or ('\'' == c) or ('"' == c) or (0x7f == c))
		{
			rv.push_back('\\');
			rv.push_back('x');
			rv.push_back(xdigits[(c >> 4) & 0xf]);
			rv.push_back(xdigits[(c     ) & 0xf]);
		}
		else
			rv.push_back(c);
	}

	return rv;
}

struct NetStream : public Object {
	enum State { NS_IDLE, NS_PUBLISHING, NS_PLAYING };

	NetStream() = delete;

	NetStream(std::shared_ptr<Client> owner, uint32_t streamID) : m_owner(owner), m_streamID(streamID)
	{}

	std::shared_ptr<Client> m_owner;
	State m_state { NS_IDLE };
	uint32_t m_streamID;
	std::string m_name;
	std::string m_hashname;
	uint32_t m_timestampOffset { 0 };
	uint32_t m_highestTimestamp { 0 };
	uint32_t m_minTimestamp { 0 };
	bool m_restarted { false };
	bool m_adjustTimestamps { true };
	bool m_paused { false };
	bool m_receiveVideo { true };
	bool m_receiveAudio { true };
	List<std::shared_ptr<WriteReceipt>> m_gopReceipts;
};

struct Stream {
	bool m_publishing { false };
	std::shared_ptr<NetStream> m_publisher;
	std::set<std::shared_ptr<NetStream>> m_subscribers;
	std::map<std::string, Bytes> m_dataFrames; // Bytes includes callback name
	Bytes m_videoInit;
	Bytes m_audioInit;
	Bytes m_lastVideoKeyframe;
	uint32_t m_lastVideoTimestamp { 0 };

	void unpublishClear()
	{
		m_publishing = false;
		m_publisher.reset();
		m_dataFrames.clear();
		m_videoInit.clear();
		m_audioInit.clear();
		m_lastVideoKeyframe.clear();
		m_lastVideoTimestamp = 0;
	}
};

class App : public Object {
public:
	App(const std::string &name) : m_name(name)
	{
		printf(",create-app,%s\n", logEscape(m_name).c_str());
	}

	~App()
	{
		printf(",destroy-app,%s\n", logEscape(m_name).c_str());
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
	void addClient(std::shared_ptr<Client> client);
	void removeClient(std::shared_ptr<Client> client);
	void broadcastMessage(const Bytes &sender, const Bytes &message);

	void subscribeStream(const std::string &hashname, std::shared_ptr<NetStream> netStream);
	void unsubscribeStream(const std::string &hashname, std::shared_ptr<NetStream> netStream);

	bool publishStream(const std::string &hashname, std::shared_ptr<NetStream> netStream); // false means stream was already being published
	void unpublishStream(const std::string &hashname);
	void releaseStream(const std::string &hashname);

	void onStreamMessage(const std::string &hashname, uint8_t messageType, uint32_t timestamp, const uint8_t *payload, size_t len);

	static bool isVideoInit(const uint8_t *payload, size_t len);
	static bool isVideoKeyframe(const uint8_t *payload, size_t len);
	static bool isVideoCheckpointCommand(const uint8_t *payload, size_t len);
	static bool isVideoSequenceSpecial(const uint8_t *payload, size_t len);

	static bool isAudioInit(const uint8_t *payload, size_t len);
	static bool isAudioSequenceSpecial(const uint8_t *payload, size_t len);

protected:
	void cleanupStream(const std::string &hashname);

	std::set<std::shared_ptr<Client>> m_clients;
	std::string m_name;
	std::map<std::string, Stream> m_streams; // by hashname
};
std::map<std::string, std::shared_ptr<App>> apps;

class Client : public Object {
public:
	static void onUnmatchedIHello(RTMFP *rtmfp, const void *epd, size_t epdLen, const void *tag, size_t tagLen, int interfaceID, const struct sockaddr *srcAddr)
	{
		FlashCryptoAdapter::EPDParseState epdParsed;
		if(not epdParsed.parse((const uint8_t *)epd, epdLen))
			return;
		if(not epdParsed.fingerprint)
			return;

		Address addr(srcAddr);
		addr.setOrigin(Address::ORIGIN_OBSERVED);

		if(verbose) printf("%s,lookup,%s\n", addr.toPresentation().c_str(), Hex::encode(epdParsed.fingerprint, epdParsed.fingerprintLen).c_str());

		auto it = clients.find(Bytes(epdParsed.fingerprint, epdParsed.fingerprint + epdParsed.fingerprintLen));
		if(it != clients.end())
			it->second->doRedirect(rtmfp, epd, epdLen, tag, tagLen, interfaceID, addr);
	}

	virtual void doRedirect(RTMFP *rtmfp, const void *epd, size_t epdLen, const void *tag, size_t tagLen, int interfaceID, const Address &addr)
	{
	}

	virtual void close()
	{
		printf("%s,close,%s,%s\n", m_farAddressStr.c_str(), Hex::encode(m_connectionID).c_str(), logEscape(m_appName).c_str());
		m_open = false;

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
			m_app->removeClient(share_ref(this));
		m_app.reset();
	}

	virtual std::shared_ptr<WriteReceipt> write(uint32_t streamID, uint8_t messageType, uint32_t timestamp, const void *payload, size_t len, Time startWithin, Time finishWithin) = 0;

	std::shared_ptr<WriteReceipt> write(uint32_t streamID, uint8_t messageType, uint32_t timestamp, const Bytes &payload, Time startWithin, Time finishWithin)
	{
		return write(streamID, messageType, timestamp, payload.data(), payload.size(), startWithin, finishWithin);
	}

	void sendRelay(const Bytes &sender, const Bytes &message)
	{
		Bytes payload;
		AMF0::String(Hex::encode(sender))->encode(payload);
		payload.insert(payload.end(), message.begin(), message.end());
		write(0, TCMSG_COMMAND, 0, Message::command("onRelay", 0, nullptr, payload), INFINITY, INFINITY);
	}

	void relayStreamMessage(std::shared_ptr<NetStream> netStream, uint8_t messageType, uint32_t timestamp, const uint8_t *payload, size_t len)
	{
		assert(NetStream::NS_PLAYING == netStream->m_state);

		uint32_t adjustedTimestamp = timestamp - netStream->m_timestampOffset;

		if(netStream->m_adjustTimestamps)
		{
			if( (netStream->m_restarted)
			 or (timestamp_lt(adjustedTimestamp, netStream->m_highestTimestamp - timestampAdjustmentMargin))
			 or (timestamp_gt(adjustedTimestamp, netStream->m_highestTimestamp + timestampAdjustmentMargin))
			)
			{
				adjustedTimestamp = netStream->m_highestTimestamp;
				netStream->m_timestampOffset = timestamp - adjustedTimestamp;
				netStream->m_minTimestamp = adjustedTimestamp;
			}

			if(timestamp_lt(adjustedTimestamp, netStream->m_minTimestamp))
				adjustedTimestamp = netStream->m_minTimestamp;
		}
		else if((0 == netStream->m_minTimestamp) and (0 == netStream->m_highestTimestamp) and (timestamp_lt(timestamp, 0)))
		{
			// this only happens if we're tuning in to a stream with current timestamps > 2^31.
			netStream->m_highestTimestamp = timestamp;
			netStream->m_minTimestamp = timestamp - 3600000;
		}

		if(timestamp and timestamp_gt(adjustedTimestamp, netStream->m_highestTimestamp))
			netStream->m_highestTimestamp = adjustedTimestamp;
		if(timestamp_lt(netStream->m_minTimestamp, netStream->m_highestTimestamp - 3600000))
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
					startWithin = videoLifetime;
					isVideoCodingLayer = true;
				}
			}
			break;

		case TCMSG_AUDIO:
			if(not App::isAudioSequenceSpecial(payload, len))
			{
				if(netStream->m_paused or not netStream->m_receiveAudio)
					return;
				startWithin = audioLifetime;
			}
			break;

		default:
			break;
		}

		auto rv = write(netStream->m_streamID, messageType, adjustedTimestamp, payload, len, startWithin, startWithin + finishByMargin);

		if(isVideoCodingLayer and rv)
		{
			auto &q = netStream->m_gopReceipts;
			std::shared_ptr<WriteReceipt> previous;
			if(not q.empty())
				previous = q.lastValue();

			if(App::isVideoKeyframe(payload, len))
			{
				previous.reset();
				if(expirePreviousGop)
				{
					Time deadline = mainRL.getCurrentTime();
					q.valuesDo([deadline] (std::shared_ptr<WriteReceipt> &each) {
						each->startBy = std::min(each->startBy, deadline);
						each->finishBy = std::min(each->finishBy, deadline);
						return true;
					});
				}
				q.clear();
			}

			rv->parent = previous;
			q.append(rv);
		}

		if(verbose and rv)
			rv->onFinished = [] (bool abandoned) { if(abandoned) { printf("-"); fflush(stdout); } };
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

		auto onStatusMessage = Message::command("onStatus", 0, nullptr,
			AMF0::Object()
				->putValueAtKey(AMF0::String("status"), "level")
				->putValueAtKey(AMF0::String("NetStream.Play.PublishNotify"), "code")
				->putValueAtKey(AMF0::String(netStream->m_name), "detail")
				->putValueAtKey(AMF0::String(netStream->m_hashname), "hashname")
				->putValueAtKey(AMF0::String("being published"), "description")
			);
		relayStreamMessage(netStream, TCMSG_COMMAND, 0, onStatusMessage.data(), onStatusMessage.size());

		for(auto it = stream.m_dataFrames.begin(); it != stream.m_dataFrames.end(); it++)
		 	relayStreamMessage(netStream, TCMSG_DATA, 0, it->second.data(), it->second.size());

		if(not stream.m_audioInit.empty())
			relayStreamMessage(netStream, TCMSG_AUDIO, 0, stream.m_audioInit.data(), stream.m_audioInit.size());
		if(not stream.m_videoInit.empty())
			relayStreamMessage(netStream, TCMSG_VIDEO, 0, stream.m_videoInit.data(), stream.m_videoInit.size());

		netStream->m_restarted = true;
		if(not stream.m_lastVideoKeyframe.empty())
			relayStreamMessage(netStream, TCMSG_VIDEO, stream.m_lastVideoTimestamp, stream.m_lastVideoKeyframe.data(), stream.m_lastVideoKeyframe.size());
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
	}

	void onMessage(uint32_t streamID, uint8_t messageType, uint32_t timestamp, const uint8_t *payload, size_t len)
	{
		if(verbose > 1)
		{
			printf("%s,debug-stream,streamID,%u,type,%d,timestamp,%u,len,%lu\n", m_farAddressStr.c_str(), streamID, messageType, timestamp, (unsigned long)len);
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
			printf("%s,error,invalid-command-format\n", m_farAddressStr.c_str());
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
			printf("%s,error,command-before-connect\n", m_farAddressStr.c_str());
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

	int validateAuth(const Args &args)
	{
		if((args.size() < 4) or not args[3]->isString())
			return -1;
		std::string authToken = args[3]->stringValue();

		Bytes nearNonce = getNearNonce();

		for(size_t x = 0; x < secrets.size(); x++)
		{
			std::string expectedAuth = hexHMACSHA256(secrets[x], m_appName);
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
			printf("%s,error,connect-missing-arg\n", m_farAddressStr.c_str());
			close();
			return;
		}

		if(m_connecting)
		{
			printf("%s,error,connect-after-connect\n", m_farAddressStr.c_str());
			close();
			return;
		}
		m_connecting = true;

		auto app = args[2]->getValueAtKey("app");
		if(not app->isString())
			app = AMF0::String("");
		m_appName = app->stringValue();

		int matchedKey = -1;
		if(secrets.size())
		{
			matchedKey = validateAuth(args);
			if(matchedKey < 0)
			{
				printf("%s,connect-reject,bad-auth,%s\n", m_farAddressStr.c_str(), logEscape(m_appName).c_str());

				write(0, TCMSG_COMMAND, 0, Message::command("_error", args[1]->doubleValue(), nullptr,
					AMF0::Object()
						->putValueAtKey(AMF0::String("error"), "level")
						->putValueAtKey(AMF0::String("NetConnection.Connect.Rejected"), "code")
						->putValueAtKey(AMF0::String("auth required"), "description")
					), INFINITY, INFINITY);

				close();
				return;
			}
		}

		auto objectEncoding = args[2]->getValueAtKey("objectEncoding");
		if(not objectEncoding->isNumber())
			objectEncoding = AMF0::Number(0);

		auto resultObject = AMF0::Object();
		resultObject->putValueAtKey(AMF0::String("status"), "level");
		resultObject->putValueAtKey(AMF0::String("NetConnection.Connect.Success"), "code");
		resultObject->putValueAtKey(AMF0::String("you connected!"), "description");
		resultObject->putValueAtKey(AMF0::String(connectionIDStr()), "connectionID");
		resultObject->putValueAtKey(objectEncoding, "objectEncoding");

		if(matchedKey >= 0)
		{
			Bytes farNonce = getFarNonce();
			if(not farNonce.empty())
				resultObject->putValueAtKey(AMF0::String(hexHMACSHA256(farNonce, hexHMACSHA256(secrets[matchedKey], m_appName))), "authToken");
		}

		printf("%s,connect,%s,%s\n", m_farAddressStr.c_str(), Hex::encode(m_connectionID).c_str(), logEscape(m_appName).c_str());

		write(0, TCMSG_COMMAND, 0, Message::command("_result", args[1]->doubleValue(), nullptr, resultObject), INFINITY, INFINITY);

		m_app = App::getApp(m_appName);
		m_app->addClient(share_ref(this));

		m_connected = true;
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

		printf("%s,createStream,%lu\n", m_farAddressStr.c_str(), (unsigned long)streamID);

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
			printf("%s,deleteStream,%lu\n", m_farAddressStr.c_str(), (unsigned long)streamID);
			m_netStreams.erase(streamID);
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
			printf("%s,relay,not-found,\n", m_farAddressStr.c_str());
			return;
		}

		Bytes msg;
		for(size_t x = 4; x < args.size(); x++)
			args[x]->encode(msg);

		printf("%s,relay,found,%s\n", m_farAddressStr.c_str(), it->second->m_farAddressStr.c_str());

		it->second->sendRelay(m_connectionID, msg);
	}

	void onBroadcastCommand(const Args &args)
	{
		ackCommandTransaction(args);

		// TODO rate limit

		Bytes msg;
		for(size_t x = 3; x < args.size(); x++)
			args[x]->encode(msg);

		printf("%s,broadcast,%s\n", m_farAddressStr.c_str(), logEscape(m_appName).c_str());

		m_app->broadcastMessage(m_connectionID, msg);
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
			printf("%s,watch,malformed,\n", m_farAddressStr.c_str());
			write(0, TCMSG_COMMAND, 0, Message::command("onDisconnected", 0, nullptr, args[3]), INFINITY, INFINITY);
			return;
		}

		auto it = clients.find(target);
		if(it == clients.end())
		{
			sendOnDisconnected(target);
			printf("%s,watch,not-found,\n", m_farAddressStr.c_str());
			return;
		}

		if(it->second.get() == this)
		{
			printf("%s,watch,self,\n", m_farAddressStr.c_str());
			return;
		}

		printf("%s,watch,found,%s\n", m_farAddressStr.c_str(), it->second->m_farAddressStr.c_str());

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

		printf("%s,releaseStream,%s,%s,%s\n", m_farAddressStr.c_str(), logEscape(m_appName).c_str(), logEscape(publishName).c_str(), hashname.c_str());

		if((App::isHashName(publishName)) or (0 == publishName.compare(0, 5, "asis:")))
			return;

		m_app->releaseStream(hashname);
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
		printf("%s,%s,%lu,%s,%s,%s\n", m_farAddressStr.c_str(), name, (unsigned long)netStream->m_streamID, logEscape(m_appName).c_str(), logEscape(netStream->m_name).c_str(), netStream->m_hashname.c_str());
	}

	void onPublishCommand(std::shared_ptr<NetStream> netStream, const Args &args)
	{
		closeStream(netStream);

		if((args.size() < 4) or not args[3]->isString())
			return; // empty or non-string publish is unpublish so we're done

		std::string publishName = args[3]->stringValue();
		std::string hashname = App::asHashName(publishName);

		if( (App::isHashName(publishName))
		 or (0 == publishName.compare(0, 5, "asis:"))
		 or (not m_app->publishStream(hashname, netStream))
		)
		{
			printf("%s,publish-reject,%lu,%s\n", m_farAddressStr.c_str(), (unsigned long)netStream->m_streamID, logEscape(publishName).c_str());

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

		logStreamEvent("publish", netStream);
		write(netStream->m_streamID, TCMSG_COMMAND, 0, Message::command("onStatus", 0, nullptr,
			AMF0::Object()
				->putValueAtKey(AMF0::String("status"), "level")
				->putValueAtKey(AMF0::String("NetStream.Publish.Start"), "code")
				->putValueAtKey(AMF0::String(publishName), "detail")
				->putValueAtKey(AMF0::String(hashname), "hashname")
				->putValueAtKey(AMF0::String("publishing"), "description")
			), INFINITY, INFINITY);
	}

	void onPlayCommand(std::shared_ptr<NetStream> netStream, const Args &args)
	{
		closeStream(netStream);

		if((args.size() < 4) or not args[3]->isString()) // empty or non-string play is unsubscribe so we're done
			return;

		std::string playName = args[3]->stringValue();
		netStream->m_name = playName;
		if(0 == playName.compare(0, 5, "asis:"))
		{
			// kind of a hack for now. should this be a parameter instead?
			// a parameter is harder to set with any existing clients.
			playName = playName.substr(5);
			netStream->m_adjustTimestamps = false;
			netStream->m_timestampOffset = netStream->m_highestTimestamp = netStream->m_minTimestamp = 0;
		}
		else
			netStream->m_adjustTimestamps = true;

		netStream->m_hashname = App::asHashName(playName);

		netStream->m_state = NetStream::NS_PLAYING;

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
	}

	void closeStream(std::shared_ptr<NetStream> netStream)
	{
		if(NetStream::NS_PUBLISHING == netStream->m_state)
		{
			logStreamEvent("unpublish", netStream);
			m_app->unpublishStream(netStream->m_hashname);
		}
		else if(NetStream::NS_PLAYING == netStream->m_state)
		{
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
		logStreamEvent(netStream->m_paused ? "pause" : "unpause", netStream);
	}

	void onReceiveVideoCommand(std::shared_ptr<NetStream> netStream, const Args &args)
	{
		if(args.size() < 4)
			return;
		netStream->m_receiveVideo = args[3]->booleanValue();
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

	uint32_t m_nextStreamID { 1 };
	bool m_connecting { false };
	bool m_connected { false };
	bool m_open { true };
	bool m_finished { false };
	std::string m_appName;
	Bytes m_connectionID;
	Address m_farAddress;
	std::string m_farAddressStr;
	std::shared_ptr<App> m_app;
	std::map<uint32_t, std::shared_ptr<NetStream>> m_netStreams;
	std::set<std::shared_ptr<Client>> m_watching;
	std::set<std::shared_ptr<Client>> m_watchedBy;
};

class RTMFPClient : public Client {
public:
	static void newClient(std::shared_ptr<RecvFlow> controlRecv)
	{
		uint32_t streamID = 0;
		if((not TCMetadata::parse(controlRecv->getMetadata(), &streamID, nullptr)) or (0 != streamID))
			return; // for now only accept TC flows.

		auto client = share_ref(new RTMFPClient(), false);

		if(allowMultipleConnections)
			client->setRandomConnectionID();
		else
		{
			auto epd = controlRecv->getFarCanonicalEPD();
			if((epd.size() == 34) and (0x21 == epd[0]) and (EPD_OPTION_FINGERPRINT == epd[1]))
				client->m_connectionID = Bytes(epd.data() + 2, epd.data() + epd.size());
			else
				client->m_connectionID = epd;
		}

		if(clients.count(client->m_connectionID))
			return; // enforce if not allowMultipleConnections

		if(not client->setup(controlRecv))
			return;

		clients[client->m_connectionID] = client;
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

		if(verbose) printf("%s,rtmfp-intro,%s\n", m_farAddressStr.c_str(), addr.toPresentation().c_str());
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

		printf("%s,setPeerInfo,rtmfp,%s", m_farAddressStr.c_str(), Hex::encode(m_connectionID).c_str());

		for(size_t x = 3; x < args.size(); x++)
		{
			if(args[x]->isString())
			{
				Address each;
				each.setOrigin(Address::ORIGIN_REPORTED);
				if(each.setFromPresentation(args[x]->stringValue()))
				{
					m_additionalAddresses.push_back(each);
					printf(",%s", each.toPresentation().c_str());
				}
			}
		}

		printf("\n");
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

		printf("%s,accept,rtmfp\n", m_farAddressStr.c_str());
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
		case TCMSG_AUDIO: return App::isAudioSequenceSpecial(bytes + rv, len - rv);
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
		printf("%s,address-change,rtmfp,%s\n", oldAddress.toPresentation().c_str(), m_farAddressStr.c_str());
	}

	void syncAudioAndData(uint32_t streamID) override
	{
		if(streamID)
		{
			auto &stream = m_netStreamTransports[streamID];
			stream.syncAudioAndData(m_nextSyncID++);
		}
	}

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

		client->m_adapter.onShutdownCompleteCallback = [client] { client->onShutdownComplete(); };
		client->m_rtmp->onmessage = [client] (uint32_t streamID, uint8_t messageType, uint32_t timestamp, const uint8_t *payload, size_t len) {
			client->onMessage(streamID, messageType, timestamp, payload, len);
		};
		client->m_rtmp->onerror = [client] { client->close(); };

		clients[client->m_connectionID] = client;
	}

	RTMPClient(bool simple) : m_adapter(&mainRL)
	{
		m_rtmp = share_ref(new RTMP(&m_adapter), false);
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

		if(not m_adapter.setSocketFd(fd))
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
	PosixStreamPlatformAdapter m_adapter;
	std::shared_ptr<RTMP> m_rtmp;
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
		client->m_wsMessageAdapter->init(client->m_websock);
		client->m_rtws = share_ref(new rtws::RTWebSocket(client->m_wsMessageAdapter), false);

		client->m_wsMessageAdapter->onOpen = [client] { client->m_rtws->init(); };
		client->m_rtws->onRecvFlow = [client] (std::shared_ptr<rtws::RecvFlow> flow) { client->acceptControlFlow(flow); };
		client->m_rtws->onError = [client] { client->close(); };

		clients[client->m_connectionID] = client;
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

		auto forwardedFor = m_websock->getHeader("x-forwarded-for");
		if(not forwardedFor.empty())
			m_farAddressStr = m_farAddress.toPresentation() + ";" + logEscape(forwardedFor);

		printf("%s,accept-control,rtws,%s\n", m_farAddressStr.c_str(), Hex::encode(m_connectionID).c_str());
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

void App::addClient(std::shared_ptr<Client> client)
{
	m_clients.insert(client);
}

void App::removeClient(std::shared_ptr<Client> client)
{
	m_clients.erase(client);
	if(m_clients.empty())
		apps.erase(m_name);
}

void App::broadcastMessage(const Bytes &sender, const Bytes &message)
{
	for(auto it = m_clients.begin(); it != m_clients.end(); it++)
		(*it)->sendRelay(sender, message);
}

void App::subscribeStream(const std::string &hashname, std::shared_ptr<NetStream> netStream)
{
	auto &stream = m_streams[hashname];
	stream.m_subscribers.insert(netStream);
	if(stream.m_publishing)
		netStream->m_owner->sendPublishNotify(netStream, stream);
}

void App::unsubscribeStream(const std::string &hashname, std::shared_ptr<NetStream> netStream)
{
	auto &stream = m_streams[hashname];
	stream.m_subscribers.erase(netStream);
	cleanupStream(hashname);
}

bool App::publishStream(const std::string &hashname, std::shared_ptr<NetStream> netStream)
{
	auto &stream = m_streams[hashname];
	if(stream.m_publishing)
		return false;
	stream.m_publishing = true;
	stream.m_publisher = netStream;

	for(auto it = stream.m_subscribers.begin(); it != stream.m_subscribers.end(); it++)
		(*it)->m_owner->sendPublishNotify(*it, stream);

	return true;
}

void App::unpublishStream(const std::string &hashname)
{
	auto &stream = m_streams[hashname];
	stream.unpublishClear();

	for(auto it = stream.m_subscribers.begin(); it != stream.m_subscribers.end(); it++)
		(*it)->m_owner->sendUnpublishNotify(*it);

	cleanupStream(hashname);
}

void App::releaseStream(const std::string &hashname)
{
	auto it = m_streams.find(hashname);
	if(it == m_streams.end())
		return;

	auto &stream = it->second;
	if(stream.m_publisher)
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
				printf(",@setDataFrame,%s,%s,%s\n", logEscape(m_name).c_str(), hashname.c_str(), logEscape(callbackName->stringValue()).c_str());
			}
			else if(0 == strcmp(commandName->stringValue(), "@clearDataFrame"))
			{
				stream.m_dataFrames.erase(callbackName->stringValue());
				printf(",@clearDataFrame,%s,%s,%s\n", logEscape(m_name).c_str(), hashname.c_str(), logEscape(callbackName->stringValue()).c_str());
				return; // does not need to be forwarded
			}
		}
	}
	else if(TCMSG_VIDEO == messageType)
	{
		if(isVideoInit(payload, len))
		{
			stream.m_videoInit = Bytes(payload, payload + len);
			stream.m_lastVideoKeyframe.clear();
		}
		else if(isVideoKeyframe(payload, len))
			stream.m_lastVideoKeyframe = Bytes(payload, payload + len);
		stream.m_lastVideoTimestamp = timestamp;
	}
	else if(TCMSG_AUDIO == messageType)
	{
		if(isAudioInit(payload, len))
			stream.m_audioInit = Bytes(payload, payload + len);
	}

	for(auto it = stream.m_subscribers.begin(); it != stream.m_subscribers.end(); it++)
		(*it)->m_owner->relayStreamMessage(*it, messageType, timestamp, actualPayload, limit - actualPayload);
}

bool App::isVideoInit(const uint8_t *payload, size_t len)
{
	return (len > 1) and (TC_VIDEO_CODEC_AVC == (payload[0] & TC_VIDEO_CODEC_MASK)) and (TC_VIDEO_AVCPACKET_AVCC == payload[1]);
}

bool App::isVideoKeyframe(const uint8_t *payload, size_t len)
{
	return len and (TC_VIDEO_FRAMETYPE_IDR == (payload[0] & TC_VIDEO_FRAMETYPE_MASK));
}

bool App::isVideoCheckpointCommand(const uint8_t *payload, size_t len)
{
	if(len < 2)
		return false;
	if(TC_VIDEO_FRAMETYPE_COMMAND != (payload[0] & TC_VIDEO_FRAMETYPE_MASK))
		return false;
	if(TC_VIDEO_CODEC_AVC == (payload[0] & TC_VIDEO_CODEC_MASK))
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
	if(0 == len)
		return true; // "video silence"
	if(len < 2)
		return false;
	if(isVideoCheckpointCommand(payload, len))
		return false;
	return (TC_VIDEO_CODEC_AVC == (payload[0] & TC_VIDEO_CODEC_MASK)) and (TC_VIDEO_AVCPACKET_NALU != payload[1]);
}

bool App::isAudioInit(const uint8_t *payload, size_t len)
{
	return (len > 1) and (TC_AUDIO_CODEC_AAC == (payload[0] & TC_AUDIO_CODEC_MASK)) and (TC_AUDIO_AACPACKET_AUDIO_SPECIFIC_CONFIG == payload[1]);
}

bool App::isAudioSequenceSpecial(const uint8_t *payload, size_t len)
{
	return (0 == len) or isAudioInit(payload, len);
}

// ---

void signal_handler(int param)
{
	interrupted = true;
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
	printf(",listen,%s,%s\n", protocolDescription(protocol).c_str(), Address(&boundAddr.s).toPresentation().c_str());

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
		printf("%s,accept,%s\n", boundAddr.toPresentation().c_str(), protocolDescription(protocol).c_str());

		switch(protocol)
		{
		case PROTO_RTMP:
			RTMPClient::newClient(newFd, false, boundAddr);
			break;

		case PROTO_RTMP_SIMPLE:
			RTMPClient::newClient(newFd, true, boundAddr);
			break;

		case PROTO_RTWS:
			RTWebSocketClient::newClient(newFd, boundAddr);
			break;

		default:
			::close(newFd);
			break;
		}
	});

	listenFds.push_back(fd);

	return true;
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
	printf("  -V sec        -- video queue lifetime (default %.3Lf)\n", videoLifetime);
	printf("  -A sec        -- audio queue lifetime (default %.3Lf)\n", audioLifetime);
	printf("  -F sec        -- finish-by margin (default %.3Lf)\n", finishByMargin);
	printf("  -r sec        -- reorder window duration (rtmfp receive, default %.3Lf)\n", reorderWindowPeriod);
	printf("  -E            -- don't expire previous GOP\n");
	printf("  -C sec        -- checkpoint queue lifetime (default %.3Lf)\n", checkpointLifetime);
	printf("  -T DSCP|name  -- set DiffServ field on outgoing packets (default %d)\n", dscp);
	printf("  -X sec        -- set congestion extra delay threshold (rtmfp, default %.3Lf)\n", delaycc_delay);
	printf("  -x            -- use static Diffie-Hellman keys instead of ephemeral\n");
	printf("  -H            -- don't require HMAC (rtmfp)\n");
	printf("  -S            -- don't require session sequence numbers (rtmfp)\n");
	printf("  -m            -- allow multiple connections per session (rtmfp)\n");
	printf("  -k key-text   -- add auth secret (text)\n");
	printf("  -K key-hex    -- add auth secret (binary hex)\n");
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
	std::vector<std::shared_ptr<RedirectorClient>> redirectors;

	while((ch = getopt(argc, argv, "V:A:F:r:EC:T:X:xHSB:b:s:w:mk:K:L:l:d:Dvh")) != -1)
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
			printf(",auth,%s,%s\n", hexHMACSHA256(secrets[0], argv[optind]).c_str(), argv[optind]);

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

	if(not ephemeralDH)
		printf(",fingerprint,%s\n", Hex::encode(crypto.getFingerprint()).c_str());

	PerformerPosixPlatformAdapter platform(&mainRL, &mainPerformer, &workerPerformer);

	bool rtmfpShutdownComplete = false;
	platform.onShutdownCompleteCallback = [&rtmfpShutdownComplete] { rtmfpShutdownComplete = true; };

	RTMFP rtmfp(&platform, &crypto);
	platform.setRtmfp(&rtmfp);

	rtmfp.setDefaultSessionKeepalivePeriod(10);
	rtmfp.setDefaultSessionRetransmitLimit(20);
	rtmfp.setDefaultSessionIdleLimit(120);

	for(auto it = rtmfpAddrs.begin(); it != rtmfpAddrs.end(); it++)
	{
		auto boundAddr = platform.addUdpInterface(it->getSockaddr());
		if(not boundAddr)
		{
			printf("rtmfp can't bind to requested address: %s\n", it->toPresentation().c_str());
			return 1;
		}
		printf(",listen,rtmfp,%s\n", boundAddr->toPresentation().c_str());
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

		redirectorClient->onReflexiveAddress = [hostname, redirectorClient_ptr] (const Address &addr) {
			printf(",redirector,%s@%s,reflexive,%s\n", hostname.c_str(), redirectorClient_ptr->getRedirectorAddress().toPresentation().c_str(), addr.toPresentation().c_str());
		};
		redirectorClient->onStatus = [hostname, redirectorClient_ptr] (RedirectorClient::Status status) {
			printf(",redirector,%s@%s,status,%d\n", hostname.c_str(), redirectorClient_ptr->getRedirectorAddress().toPresentation().c_str(), status);
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
	::signal(SIGTERM, signal_handler);

	mainRL.onEveryCycle = [&rtmfp, &rtmfpShutdownComplete, &listenFds, &redirectors] {
		if(interrupted)
		{
			interrupted = false;
			printf(",interrupted,%s\n", stopping ? "quitting" : "shutting down...");
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

			for(auto it = listenFds.begin(); it != listenFds.end(); it++)
			{
				mainRL.unregisterDescriptor(*it);
				::close(*it);
			}
			listenFds.clear();

			for(auto it = redirectors.begin(); it != redirectors.end(); it++)
				(*it)->close();

			rtmfp.shutdown(true);
			fflush(stdout);
		}

		if(stopping and clients.empty() and rtmfpShutdownComplete)
			mainRL.stop();
	};

	mainRL.scheduleRel(Timer::makeAction([] { fflush(stdout); }), 0, 2);

	auto workerThread = std::thread([] { workerRL.run(); });

	printf(",run\n");
	mainRL.run();

	workerPerformer.perform([] { workerRL.stop(); });
	workerThread.join();

	mainPerformer.close();
	workerPerformer.close();

	printf(",end\n");

	return 0;
}
