// Copyright © 2021 Michael Thornburgh
// SPDX-License-Identifier: MIT

// TODO:
//  * option for RO_NETWORK for video/audio rx flows with time-bounded reordering
//  * don't relay setPeerInfo
//  * send an empty setPeerInfo on RTMFP after connect
//  * happy eyeballs for RTMP (handle multiple addresses from getaddrinfo))
//  * use URIs for dest
//    - rewrite connect tcUrl
//  * RTMPS (at least output)

#include <cassert>
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
#include "rtmfp/SelectRunLoop.hpp"
#include "rtmfp/FlashCryptoAdapter_OpenSSL.hpp"
#include "rtmfp/PerformerPosixPlatformAdapter.hpp"
#include "rtmfp/TCMessage.hpp"
#include "rtmfp/FlowSyncManager.hpp"

#include "RTMP.hpp"
#include "PosixRTMPPlatformAdapter.hpp"

using namespace com::zenomt;
using namespace com::zenomt::rtmfp;
using namespace com::zenomt::rtmp;

namespace {

class Connection; class Client;

enum Protocol { PROTO_UNSPEC, PROTO_RTMP, PROTO_RTMP_SIMPLE, PROTO_RTMFP };

int verbose = 0;
int port = 1935;
bool requireHMAC = true;
bool requireSSEQ = true;
bool interleave = false;
Time videoLifetime = 2.0;
Time audioLifetime = 2.2;
Time finishByMargin = 0.1;
Time previousGopLifetime = 0.1;
bool expirePreviousGop = true;
bool interrupted = false;
bool stopping = false;
Protocol inputProtocol = PROTO_UNSPEC;
Protocol outputProtocol = PROTO_UNSPEC;
const char *desthostname = nullptr;
const char *destservname = "1935";
const char *rtmfpUri = "rtmfp:";

SelectRunLoop mainRL;
Performer mainPerformer(&mainRL);
SelectRunLoop workerRL;
Performer workerPerformer(&workerRL);
SelectRunLoop lookupRL;
Performer lookupPerformer(&lookupRL);

std::set<std::shared_ptr<Client>> clients;

void lookup(const std::function<void(struct addrinfo *results)> &onresult)
{
	lookupPerformer.perform([onresult] {
		struct addrinfo *res0 = nullptr;
		int error = getaddrinfo(desthostname, destservname, nullptr, &res0);
		if(error)
			printf("getaddrinfo: %s\n", gai_strerror(error));
		mainPerformer.perform([onresult, res0] {
			onresult(res0);
			freeaddrinfo(res0);
		});
	});
}

class Connection : public Object {
public:
	~Connection()
	{
		if(verbose > 1) printf("~Connection %p\n", (void *)this);
	}

	virtual void close() { m_open = false; }
	virtual void shutdown() = 0;

	bool isFinished() const { return m_finished; }

	std::shared_ptr<WriteReceipt> write(uint32_t streamID, uint8_t messageType, uint32_t timestamp, const void *payload, size_t len)
	{
		const uint8_t *data = (const uint8_t *)payload;
		Time startWithin = INFINITY;

		switch(messageType)
		{
		case TCMSG_VIDEO:
			if(not isVideoSequenceSpecial(data, len))
				startWithin = videoLifetime;
			break;

		case TCMSG_AUDIO:
			if(not isAudioSequenceSpecial(data, len))
				startWithin = audioLifetime;
			break;
		}

		Time finishWithin = startWithin + finishByMargin;

		auto rv = basicWrite(streamID, messageType, timestamp, data, len, startWithin, finishWithin);

		if(rv and (TCMSG_VIDEO == messageType))
		{
			auto &q = m_receiptsByStream[streamID];
			std::shared_ptr<WriteReceipt> previous;
			if(not q.empty())
				previous = q.lastValue();

			if(len and (0x10 == (data[0] & 0xf0))) // keyframe/IDR
			{
				previous.reset();
				if(expirePreviousGop)
				{
					Time deadline = mainRL.getCurrentTime() + previousGopLifetime;
					q.valuesDo([deadline] (std::shared_ptr<WriteReceipt> &each) { each->startBy = std::min(each->startBy, deadline); return true; });
				}
				q.clear();
			}

			if(startWithin < INFINITY)
			{
				rv->parent = previous;
				q.append(rv);
			}
		}

		if(rv and verbose)
			rv->onFinished = [] (bool abandoned) { if(abandoned) { printf("-"); fflush(stdout); } };

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
		if(0 == len)
			return true;
		if(len < 2)
			return false;
		return (0x07 == (payload[0] & 0x0f)) and (0x01 != payload[1]);
			return true;
	}

	bool isAudioSequenceSpecial(const uint8_t *payload, size_t len) const
	{
		if(0 == len)
			return true;
		if(len < 2)
			return false;
		return (0xa0 == (payload[0] & 0xf0)) and (0 == payload[1]);
	}

	std::map<uint32_t, List<std::shared_ptr<WriteReceipt>>> m_receiptsByStream;
	bool m_open = { true };
	bool m_finished = { false };
};

class RTMPConnection : public Connection {
public:
	RTMPConnection(bool isServer) : m_adapter(&mainRL), m_connectionOpen(false)
	{
		m_rtmp = share_ref(new RTMP(&m_adapter), false);
		m_adapter.setRTMP(m_rtmp.get());
		m_rtmp->init(isServer);

		m_rtmp->onmessage = [this] (uint32_t streamID, uint8_t messageType, uint32_t timestamp, const uint8_t *payload, size_t len) {
			if((TCMSG_USER_CONTROL == messageType) and (len >= 2) and (((TC_USERCONTROL_FLOW_SYNC >> 8) & 0xff) == payload[0]) and ((TC_USERCONTROL_FLOW_SYNC & 0xff) == payload[1]))
			{
				if(verbose)
					printf("ignoring TC_USERCONTROL_FLOW_SYNC from RTMP\n");
				return;
			}

			if(onmessage)
				onmessage(streamID, messageType, timestamp, payload, len);
		};

		m_rtmp->onerror = [this] { callOnError(); };
		m_adapter.onShutdownCompleteCallback = [this] { callOnShutdownComplete(); };

		if(PROTO_RTMP_SIMPLE == (isServer ? inputProtocol : outputProtocol))
		{
			m_rtmp->setSimpleMode(true);
			m_rtmp->setChunkSize(1<<24); // maximum message size
		}
	}

	bool setFd(int fd)
	{
		if(not m_adapter.setSocketFd(fd))
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
		lookup([this, myself] (struct addrinfo *results) {
			if(m_open)
			{
				if(not results)
					goto error;

				if(verbose) printf("connecting to %s\n", Address(results->ai_addr).toPresentation().c_str());

				int fd = socket(results->ai_family, SOCK_STREAM, IPPROTO_TCP);
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
				if((connect(fd, results->ai_addr, results->ai_addrlen) < 0) and (EINPROGRESS != errno))
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
		m_adapter.close();
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

	PosixRTMPPlatformAdapter m_adapter;
	std::shared_ptr<RTMP> m_rtmp;
	bool m_connectionOpen;
};

class RTMFPConnection : public Connection {
public:
	void close() override
	{
		Connection::close();
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

		setOnMessage(controlRecv, 0);

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
			std::shared_ptr<SendFlow> *flowRef = &m_data;
			if(TCMSG_VIDEO == messageType)
			{
				flowRef = &m_video;
				if(not interleave)
					pri = PRI_PRIORITY; // lower than audio/data but still time-critical
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

	void setOnMessage(const std::shared_ptr<RecvFlow> &flow, uint32_t streamID)
	{
		flow->onMessage = [this, streamID, flow] (const uint8_t *bytes, size_t len, uintmax_t sequenceNumber, size_t fragmentCount) {
			uint32_t syncID = 0;
			size_t count = 0;
			if(FlowSyncManager::parse(bytes, len, syncID, count))
			{
				m_syncManager.sync(syncID, count, flow);
				return;
			}

			uint8_t messageType = 0;
			uint32_t timestamp = 0;
			size_t rv = TCMessage::parseHeader(bytes, bytes + len, &messageType, &timestamp);
			if(0 == rv)
				return;

			if(onmessage)
				onmessage(streamID, messageType, timestamp, bytes + rv, len - rv);
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
		flow->setBufferCapacity(1<<24); // 16MB, big enough for largest TCMessage

		flow->onComplete = [this, flow] (bool error) { m_recvFlows.erase(flow); checkFinishedLater(); };
		setOnMessage(flow, streamID);

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

	void openConnection()
	{
		m_controlSend = m_rtmfp->openFlow(m_crypto.makeEPD(nullptr, "rtmfp:", nullptr), TCMetadata::encode(0, RO_SEQUENCE), PRI_IMMEDIATE);
		wireControlSend();

		m_platform.addUdpInterface(0, AF_INET);
		m_platform.addUdpInterface(0, AF_INET6);

		auto myself = share_ref(this);
		lookup([this, myself] (struct addrinfo *results) {
			if(m_open)
			{
				for(struct addrinfo *each = results; each; each = each->ai_next)
					m_controlSend->addCandidateAddress(each->ai_addr);
			}
		});
	}

	std::shared_ptr<WriteReceipt> basicWrite(uint32_t streamID, uint8_t messageType, uint32_t timestamp, const uint8_t *payload, size_t len, Time startWithin, Time finishWithin) override
	{
		if(not m_controlSend)
			openConnection();

		return RTMFPConnection::basicWrite(streamID, messageType, timestamp, payload, len, startWithin, finishWithin);
	}

	FlashCryptoAdapter_OpenSSL m_crypto;
	PerformerPosixPlatformAdapter m_platform;
	std::shared_ptr<RTMFP> m_rtmfp;
	bool m_rtmfpShutdownComplete { false };
};

class Client : public Object {
public:
	~Client()
	{
		if(verbose > 1) printf("~Client %p\n", (void *)this);
	}

	static void newRTMPClient(int fd)
	{
		auto rv = share_ref(new RTMPConnection(true), false);
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
			m_outgoing = share_ref(new RTMPConnection(false), false);
	}

	void wireConnections()
	{
		m_incoming->onmessage = [this] (uint32_t streamID, uint8_t messageType, uint32_t timestamp, const uint8_t *payload, size_t len) {
			if(verbose > 1) printf("incoming onmessage streamID:%u, messageType:%u, ts:%u, len:%lu\n", streamID, messageType, timestamp, (unsigned long)len);
			m_outgoing->write(streamID, messageType, timestamp, payload, len);
		};

		m_outgoing->onmessage = [this] (uint32_t streamID, uint8_t messageType, uint32_t timestamp, const uint8_t *payload, size_t len) {
			if(verbose > 1) printf("outgoing onmessage streamID:%u, messageType:%u, ts:%u, len:%lu\n", streamID, messageType, timestamp, (unsigned long)len);
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

bool listenRTMP(const Address &addr)
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

		if(verbose) printf("accepted RTMP from %s\n", Address(&boundAddr.s).toPresentation().c_str());
		Client::newRTMPClient(newFd);
	});

	return true;
}

bool listenRTMP(int port, int family)
{
	Address addr;
	if(not addr.setFamily(family))
		return false;
	addr.setPort(port);
	return listenRTMP(addr);
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
	printf("  -i proto      -- listen for proto (rtmp|rtmp-simple|rtmfp)\n");
	printf("  -o proto      -- relay to proto (rtmp|rtmp-simple|rtmfp)\n");
	printf("  -I            -- interleave A/V on same flow/priority\n");
	printf("  -V sec        -- video queue lifetime (default %.3Lf)\n", videoLifetime);
	printf("  -A sec        -- audio queue lifetime (default %.3Lf)\n", audioLifetime);
	printf("  -F sec        -- finish-by margin (default %.3Lf)\n", finishByMargin);
	printf("  -E            -- don't expire previous GOP\n");
	printf("  -H            -- don't require HMAC (rtmfp)\n");
	printf("  -S            -- don't require session sequence numbers (rtmfp)\n");
	printf("  -p port       -- port for -4/-6 (default %d)\n", port);
	printf("  -4            -- bind to IPv4 0.0.0.0:%d\n", port);
	printf("  -6            -- bind to IPv6 [::]:%d\n", port);
	printf("  -B addr:port  -- bind to addr:port explicitly\n");
	printf("  -u uri        -- set URI for IHello (rtmfp, default \"%s\")\n", rtmfpUri);
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

	while((ch = getopt(argc, argv, "i:o:IV:A:F:EHSp:46B:u:vh")) != -1)
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
		case 'E':
			expirePreviousGop = false;
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
			{
				Address addr;
				if(not addr.setFromPresentation(optarg))
				{
					printf("can't parse address %s\n", optarg);
					return 1;
				}
				bindAddrs.push_back(addr);
			}
			break;
		case 'p':
			port = atoi(optarg);
			break;
		case 'u':
			rtmfpUri = optarg;
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
	}
	else
	{
		for(auto it = bindAddrs.begin(); it != bindAddrs.end(); it++)
			if(not listenRTMP(*it))
				return 1;
		if(ipv4 and not listenRTMP(port, AF_INET))
			return 1;
		if(ipv6 and not listenRTMP(port, AF_INET6))
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
