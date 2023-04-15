// Copyright © 2023 Michael Thornburgh
// SPDX-License-Identifier: MIT

/*

conncheck
=========

This is an RTMFP connectivity checking server. The server probes a connected
RFC 7425 client to characterize its behavior and that of the NATs or firewalls
between it and the server. This is primarily useful to judge whether P2P
connections are likely to work and to diagnose connectivity issues.

The server probes the client with IHello packets sent from multiple IP
addresses and UDP ports, and watches for RHello packets from the client to
judge if the probes got through. The server also uses Forwarded IHello (FIHello)
to determine whether the client is behind a "symmetric NAT" that uses different
translated ports or IP addresses for different destinations.

The server initiates the checks on receiving a `setPeerInfo` command
(RFC 7425 §5.3.3). Test results are returned to the client in a
`NetConnection.ConnectivityCheck.Results` status event. The results
include:

  * `publicAddress`: The IP address and UDP port of the client as observed
    by the server.

  * `publicAddressIsLocal`: Whether the client's public address appeared
    in the list of addresses sent in the `setPeerInfo` command. If the list
    list was empty, this is `undefined`.

  * `publicPortMatchesLocalPort`: Whether the UDP port of the client's public
    address appears as the port of any address in the `setPeerInfo` list,
    indicating the client's port may be preserved through translation even if
    the IP address is different. If the list was empty, this is `undefined`.

  * `receiveSameAddressDifferentPortAllowed`: Whether the client can receive
    an unsolicited packet from the same IP address as the server but from a
    different port.

  * `receiveDifferentAddressDifferentPortAllowed`: Whether the client can
    receive an unsolicited packet from a different IP address and port.

  * `sendAfterIntroductionAllowed`: Whether the client responds to an FIHello
    with an RHello, and that packet can get through to a different IP
    address and port.

  * `sendAfterIntroductionPreservesSourceAddress`: Whether the response to
    the FIHello above came from the same IP address as the client's
    connection to the server.

  * `sendAfterIntroductionPreservesSourcePort`: Whether the response to the
    FIHello above came from the same UDP port as the client's connection
    to the server.

The server closes the connection after reporting the results.

The server requires a host with three distinct IP addresses to perform these
tests. For consistency of results, the addresses should all be in the same
address family (that is, all IPv4 or all IPv6). Run separate servers for IPv4
and IPv6.

Clients should be configured to treat the server as a Forwarder (RFC 7016
§3.5.1.5), and to respond to FIHellos from the server with an RHello (see
RFC 7016 §2.3.3, §3.5.1.5, and `Flow::setSessionFIHelloMode()`).

Example usage:

  # host has 3 directly-attached public IPv4 addresses
  $ ./conncheck -B 192.0.2.129:1935 -p 19350 -a 192.0.2.130:19351 -i 192.0.2.131:19352

  # host has 3 translated/private IPv4 addresses mapped to distinct public addresses
  $ ./conncheck -B 10.0.2.2:1935 -p 19350 -a 10.0.2.3:19351 -i 10.0.2.4:19352 -I 192.0.2.131:19352

  # host has 3 directly-attached IPv6 addresses
  $ ./conncheck -B '[2001:db8:1::2]:1935' -p 19350 -a '[2001:db8:1::1:2]:19351' -i '[2001:db8:1::2:2]:19352'

*/

#include <cassert>
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>

extern "C" {
#include <unistd.h>
}

#include "rtmfp/rtmfp.hpp"
#include "rtmfp/RunLoops.hpp"
#include "rtmfp/FlashCryptoAdapter_OpenSSL.hpp"
#include "rtmfp/PerformerPosixPlatformAdapter.hpp"
#include "rtmfp/TCMessage.hpp"
#include "rtmfp/Hex.hpp"

using namespace com::zenomt;
using namespace com::zenomt::rtmfp;
using namespace com::zenomt::rtmp;

using Args = std::vector<std::shared_ptr<AMF0>>;

namespace {

int verbose = 0;
bool requireHMAC = true;
bool requireSSEQ = true;
Time testOffset = 0.020;
size_t tries = 5;
Time connectionTimeout = 120.0;
bool interrupted = false;
bool stopping = false;

Address introReplyAddress;
const char *serverInfo = nullptr;
int differentPortInterface = -1;
int differentAddressInterface = -1;
int introReplyInterface = -1;

PreferredRunLoop mainRL;
Performer mainPerformer(&mainRL);
PreferredRunLoop workerRL;
Performer workerPerformer(&workerRL);
FlashCryptoAdapter *flashcrypto = nullptr; // set in main()
RTMFP *probeRtmfpPtr = nullptr;


class Client;
std::map<Bytes, std::shared_ptr<Client>> clients;

class NotMeFlashCryptoAdapter : public FlashCryptoAdapter_OpenSSL {
public:
	bool isSelectedByEPD(const uint8_t *epd, size_t epdLen) override
	{
		return false;
	}
};

class Client : public Object {
public:
	~Client()
	{
		if(verbose > 2)
			printf("~Client %p\n", (void *)this);
	}

	static void newClient(std::shared_ptr<RecvFlow> controlRecv)
	{
		uint32_t streamID = 0;
		if((not TCMetadata::parse(controlRecv->getMetadata(), &streamID, nullptr)) or (0 != streamID))
			return; // for now only accept TC flows.

		auto client = share_ref(new Client(), false);
		if(verbose > 2)
			printf("new Client %p\n", (void *)client.get());

		if(not client->setup(controlRecv))
			return;

		clients[client->m_probeTag] = client;
	}

	static void onUnmatchedRHello(const uint8_t *tag, size_t tagLen, const uint8_t *cookie, size_t cookieLen, const uint8_t *cert, size_t certLen, int interfaceID, const struct sockaddr *srcAddr)
	{
		Address address(srcAddr);

		auto it = clients.find(Bytes(tag, tag + tagLen));
		if(it != clients.end())
			it->second->onProbeReturned(interfaceID, address);
	}

	void close()
	{
		retain();

		if(verbose) printf("%s,close\n", m_farAddressStr.c_str());
		m_open = false;

		if(m_controlSend)
			m_controlSend->close();
		if(m_controlRecv)
			m_controlRecv->close(); // needed for AIR compatibility; this is not good, clean close should be on all RecvFlows closing.

		m_otherFlows.valuesDo([] (const std::shared_ptr<RecvFlow> each) { each->close(); return true; });
		m_otherFlows.clear();

		clients.erase(m_probeTag);

		if(m_differentPortTimer)
			m_differentPortTimer->cancel();
		if(m_differentAddressTimer)
			m_differentAddressTimer->cancel();
		if(m_introTimer)
			m_introTimer->cancel();
		if(m_timeoutTimer)
			m_timeoutTimer->cancel();
		if(m_connectionTimeoutTimer)
			m_connectionTimeoutTimer->cancel();

		release();
	}

protected:
	std::shared_ptr<WriteReceipt> write(uint32_t streamID, uint8_t messageType, uint32_t timestamp, const void *payload, size_t len, Time startWithin, Time finishWithin)
	{
		if(0 == streamID)
			return m_controlSend->write(TCMessage::message(messageType, timestamp, (const uint8_t *)payload, len), startWithin, finishWithin);
		return nullptr;
	}

	std::shared_ptr<WriteReceipt> write(uint32_t streamID, uint8_t messageType, uint32_t timestamp, const Bytes &payload, Time startWithin, Time finishWithin)
	{
		return write(streamID, messageType, timestamp, payload.data(), payload.size(), startWithin, finishWithin);
	}

	bool setup(std::shared_ptr<RecvFlow> controlRecv)
	{
		m_controlRecv = controlRecv;
		m_controlSend = m_controlRecv->openReturnFlow(TCMetadata::encode(0, RO_SEQUENCE), PRI_IMMEDIATE);
		if(not m_controlSend)
			return false;

		m_controlSend->onException = [this] (uintmax_t reason) { close(); };
		m_controlSend->onRecvFlow = [this] (std::shared_ptr<RecvFlow> flow) { acceptOtherFlow(flow); };

		m_controlRecv->onComplete = [this] (bool error) { close(); };
		m_controlRecv->onFarAddressDidChange = [this] { onFarAddressDidChange(); };
		setOnMessage(m_controlRecv, 0);

		m_epd = m_controlRecv->getFarCanonicalEPD();

		m_farAddress = m_controlRecv->getFarAddress();
		m_farAddressStr = m_farAddress.toPresentation();
		if(verbose) printf("%s,accept,rtmfp\n", m_farAddressStr.c_str());
		m_controlRecv->accept();

		m_probeTag.resize(32);
		flashcrypto->pseudoRandomBytes(m_probeTag.data(), m_probeTag.size());

		m_connectionTimeoutTimer = mainRL.scheduleRel([this] (const std::shared_ptr<Timer> &sender, Time now) { close(); }, connectionTimeout);

		return true;
	}

	void acceptOtherFlow(std::shared_ptr<RecvFlow> flow)
	{
		uint32_t streamID = 0;
		if(not TCMetadata::parse(flow->getMetadata(), &streamID, nullptr)) // only TC flows for now
			return;

		if(streamID)
			return; // reject if not for stream ID 0, we don't do createStream

		flow->onComplete = [this] (bool error) { close(); };

		setOnMessage(flow, streamID);

		flow->accept();
		m_otherFlows.append(flow);
	}

	void deliverMessage(uint32_t streamID, const uint8_t *bytes, size_t len)
	{
		uint8_t messageType = 0;
		uint32_t timestamp = 0;
		size_t rv = TCMessage::parseHeader(bytes, bytes + len, &messageType, &timestamp);
		if(rv)
			onMessage(streamID, messageType, timestamp, bytes + rv, len - rv);
	}

	void setOnMessage(const std::shared_ptr<RecvFlow> &flow, uint32_t streamID)
	{
		flow->onMessage = [this, streamID] (const uint8_t *bytes, size_t len, uintmax_t sequenceNumber, size_t fragmentCount) {
			deliverMessage(streamID, bytes, len);
		};
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

		default:
			break;
		}
	}

	void ackCommandTransaction(const Args &args)
	{
		if(args[1]->doubleValue() > 0.0)
			write(0, TCMSG_COMMAND, 0, Message::command("_result", args[1]->doubleValue(), nullptr, AMF0::Undefined()), INFINITY, INFINITY);
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
			if(verbose > 1)
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

		if(0 == strcmp("setPeerInfo", commandName))
			onSetPeerInfoCommand(args);
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

		auto objectEncoding = args[2]->getValueAtKey("objectEncoding");
		if(not objectEncoding->isNumber())
			objectEncoding = AMF0::Number(0);

		auto resultObject = AMF0::Object();
		resultObject->putValueAtKey(AMF0::String("status"), "level");
		resultObject->putValueAtKey(AMF0::String("NetConnection.Connect.Success"), "code");
		resultObject->putValueAtKey(AMF0::String("you connected!"), "description");
		resultObject->putValueAtKey(objectEncoding, "objectEncoding");
		if(serverInfo)
		{
			resultObject->putValueAtKey(AMF0::String(serverInfo), "serverInfo");
			resultObject->putValueAtKey(AMF0::String(serverInfo), "motd");
		}

		if(verbose) printf("%s,connect\n", m_farAddressStr.c_str());

		write(0, TCMSG_COMMAND, 0, Message::command("_result", args[1]->doubleValue(), nullptr, resultObject), INFINITY, INFINITY);

		m_connected = true;
	}

	void onSetPeerInfoCommand(const Args &args)
	{
		m_additionalAddresses.clear();
		m_publicAddressIsLocal = false;
		m_publicPortMatchesLocalPort = false;

		if(verbose) printf("%s,setPeerInfo,rtmfp", m_farAddressStr.c_str());

		for(size_t x = 3; x < args.size(); x++)
		{
			if(args[x]->isString())
			{
				Address each;
				each.setOrigin(Address::ORIGIN_REPORTED);
				if(each.setFromPresentation(args[x]->stringValue()))
				{
					m_additionalAddresses.push_back(each);
					if(verbose) printf(",%s", each.toPresentation().c_str());

					if(m_farAddress == each)
						m_publicAddressIsLocal = true;
					if(m_farAddress.getPort() == each.getPort())
						m_publicPortMatchesLocalPort = true;
				}
			}
		}

		if(verbose) printf("\n");

		startTests();

		ackCommandTransaction(args);
	}

	void startTests()
	{
		if(m_testsStarted)
			return;
		m_testsStarted = true;

		Time rto = m_controlRecv->getERTO();

		m_differentPortTimer = mainRL.scheduleRel([this] (const std::shared_ptr<Timer> &sender, Time now) {
			if(verbose) printf("%s,send-probe,same-address-different-port\n", m_farAddressStr.c_str());
			probeRtmfpPtr->sendIHello(m_epd.data(), m_epd.size(), m_probeTag.data(), m_probeTag.size(), differentPortInterface, m_farAddress.getSockaddr());
		}, testOffset, rto);

		m_differentAddressTimer = mainRL.scheduleRel([this] (const std::shared_ptr<Timer> &sender, Time now) {
			if(verbose) printf("%s,send-probe,different-address\n", m_farAddressStr.c_str());
			probeRtmfpPtr->sendIHello(m_epd.data(), m_epd.size(), m_probeTag.data(), m_probeTag.size(), differentAddressInterface, m_farAddress.getSockaddr());
		}, testOffset * 2.0, rto);

		m_introTimer = mainRL.scheduleRel([this] (const std::shared_ptr<Timer> &sender, Time now) {
			if(verbose) printf("%s,send-probe,intro\n", m_farAddressStr.c_str());
			m_controlRecv->forwardIHello(m_epd.data(), m_epd.size(), introReplyAddress.getSockaddr(), m_probeTag.data(), m_probeTag.size());
		}, testOffset * 3.0, rto);

		m_timeoutTimer = mainRL.scheduleRel([this] (const std::shared_ptr<Timer> &sender, Time now) {
			if(m_differentPortTimer)
				m_differentPortTimer->cancel();
			if(m_differentAddressTimer)
				m_differentAddressTimer->cancel();
			if(m_introTimer)
				m_introTimer->cancel();
			sendTestResultsIfDone();
		}, testOffset * 3.0 + rto * tries);

	}

	void onFarAddressDidChange()
	{
		if(verbose) printf("%s,address-change,rtmfp", m_farAddressStr.c_str());
		m_farAddress = m_controlRecv->getFarAddress();
		m_farAddressStr = m_farAddress.toPresentation();
		if(verbose) printf("%s\n", m_farAddressStr.c_str());
		write(0, TCMSG_COMMAND, 0, Message::command("onStatus", 0, nullptr,
			AMF0::Object()
				->putValueAtKey(AMF0::String("status"), "level")
				->putValueAtKey(AMF0::String("NetConnection.AddressChange.Notify"), "code")
			), INFINITY, INFINITY);
	}

	void onProbeReturned(int interfaceID, const Address &address)
	{
		if(interfaceID == differentPortInterface)
			onDifferentPortProbeReturned(address);
		else if(interfaceID == differentAddressInterface)
			onDifferentAddressProbeReturned(address);
		else if(interfaceID == introReplyInterface)
			onIntroReply(address);
	}

	void onDifferentPortProbeReturned(const Address &address)
	{
		if(m_differentPortTimer)
			m_differentPortTimer->cancel();

		m_receiveSameAddressDifferentPortAllowed = true;

		if(verbose) printf("%s,probe-returned,same-address-different-port,%s\n", m_farAddressStr.c_str(), address.toPresentation().c_str());

		sendTestResultsIfDone();
	}

	void onDifferentAddressProbeReturned(const Address &address)
	{
		if(m_differentAddressTimer)
			m_differentAddressTimer->cancel();

		m_receiveDifferentAddressDifferentPortAllowed = true;

		if(verbose) printf("%s,probe-returned,different-address,%s\n", m_farAddressStr.c_str(), address.toPresentation().c_str());

		sendTestResultsIfDone();
	}

	void onIntroReply(const Address &address)
	{
		if(m_introTimer)
			m_introTimer->cancel();

		m_sendAfterIntroductionAllowed = true;
		m_sendAfterIntroductionPreservesSourceAddress = address == m_farAddress;
		m_sendAfterIntroductionPreservesSourcePort = address.getPort() == m_farAddress.getPort();

		if(verbose) printf("%s,probe-returned,intro,%s\n", m_farAddressStr.c_str(), address.toPresentation().c_str());

		sendTestResultsIfDone();
	}

	void sendTestResultsIfDone()
	{
		if(  ((not m_differentPortTimer) or m_differentPortTimer->isCanceled())
		 and ((not m_differentAddressTimer) or m_differentAddressTimer->isCanceled())
		 and ((not m_introTimer) or m_introTimer->isCanceled())
		)
		{
			std::shared_ptr<AMF0> publicAddressIsLocal = AMF0::Boolean(m_publicAddressIsLocal);
			std::shared_ptr<AMF0> publicPortMatchesLocalPort = AMF0::Boolean(m_publicPortMatchesLocalPort);

			if(m_additionalAddresses.empty())
				publicAddressIsLocal = publicPortMatchesLocalPort = AMF0::Undefined();

			write(0, TCMSG_COMMAND, 0, Message::command("onStatus", 0, nullptr, AMF0::Object()
				->putValueAtKey(AMF0::String("status"), "level")
				->putValueAtKey(AMF0::String("NetConnection.ConnectivityCheck.Results"), "code")
				->putValueAtKey(AMF0::String("Connectivity Check results"), "description")
				->putValueAtKey(AMF0::String(m_farAddressStr), "publicAddress")
				->putValueAtKey(publicAddressIsLocal, "publicAddressIsLocal")
				->putValueAtKey(publicPortMatchesLocalPort, "publicPortMatchesLocalPort")
				->putValueAtKey(AMF0::Boolean(m_receiveSameAddressDifferentPortAllowed), "receiveSameAddressDifferentPortAllowed")
				->putValueAtKey(AMF0::Boolean(m_receiveDifferentAddressDifferentPortAllowed), "receiveDifferentAddressDifferentPortAllowed")
				->putValueAtKey(AMF0::Boolean(m_sendAfterIntroductionAllowed), "sendAfterIntroductionAllowed")
				->putValueAtKey(AMF0::Boolean(m_sendAfterIntroductionPreservesSourceAddress), "sendAfterIntroductionPreservesSourceAddress")
				->putValueAtKey(AMF0::Boolean(m_sendAfterIntroductionPreservesSourcePort), "sendAfterIntroductionPreservesSourcePort")
			), INFINITY, INFINITY);

			printf("%s,results,publicAddressIsLocal,%s,publicPortMatchesLocalPort,%s,receiveSameAddressDifferentPortAllowed,%s,receiveDifferentAddressDifferentPortAllowed,%s,sendAfterIntroductionAllowed,%s,sendAfterIntroductionPreservesSourceAddress,%s,sendAfterIntroductionPreservesSourcePort,%s\n",
				m_farAddressStr.c_str(),
				publicAddressIsLocal->repr().c_str(),
				publicPortMatchesLocalPort->repr().c_str(),
				m_receiveSameAddressDifferentPortAllowed ? "true" : "false",
				m_receiveDifferentAddressDifferentPortAllowed ? "true" : "false",
				m_sendAfterIntroductionAllowed ? "true" : "false",
				m_sendAfterIntroductionPreservesSourceAddress ? "true" : "false",
				m_sendAfterIntroductionPreservesSourcePort ? "true" : "false");

			m_timeoutTimer->cancel();
			m_controlSend->close();
		}
	}

	bool m_connecting { false };
	bool m_connected { false };
	bool m_open { true };
	bool m_testsStarted { false };
	std::shared_ptr<SendFlow> m_controlSend;
	std::shared_ptr<RecvFlow> m_controlRecv;
	std::vector<Address> m_additionalAddresses;
	List<std::shared_ptr<RecvFlow>> m_otherFlows;
	Address m_farAddress;
	std::string m_farAddressStr;
	Bytes m_probeTag;
	Bytes m_epd;

	std::shared_ptr<Timer> m_differentPortTimer;
	std::shared_ptr<Timer> m_differentAddressTimer;
	std::shared_ptr<Timer> m_introTimer;
	std::shared_ptr<Timer> m_timeoutTimer;
	std::shared_ptr<Timer> m_connectionTimeoutTimer;
	bool m_publicAddressIsLocal { false };
	bool m_publicPortMatchesLocalPort { false };
	bool m_receiveSameAddressDifferentPortAllowed { false };
	bool m_receiveDifferentAddressDifferentPortAllowed { false };
	bool m_sendAfterIntroductionAllowed { false };
	bool m_sendAfterIntroductionPreservesSourceAddress { false };
	bool m_sendAfterIntroductionPreservesSourcePort { false };
};

// ---

void signal_handler(int param)
{
	interrupted = true;
}

bool setAddressFromPresentation(const char *presentationForm, Address &dst)
{
	if(not dst.setFromPresentation(presentationForm))
		return false;
	dst.setOrigin(Address::ORIGIN_REPORTED);
	return true;
}

int usage(const char *prog, int rv, const char *msg = nullptr, const char *arg = nullptr)
{
	if(msg)
		printf("%s", msg);
	if(arg)
		printf("%s", arg);
	if(msg or arg)
		printf("\n");

	printf("usage: %s -B addr:port -p addr:port -a addr:port -i addr:port [options]\n", prog);
	printf("  -B addr:port  -- listen for rtmfp connections on addr:port\n");
	printf("  -p port       -- different port on bind address\n");
	printf("  -a addr:port  -- different address\n");
	printf("  -i addr:port  -- introduction reply address\n");
	printf("  -I addr:port  -- public introduction reply address (if different)\n");
	printf("  -m message    -- set serverInfo message\n");
	printf("  -t tries      -- send up to tries probes (default %zu)\n", tries);
	printf("  -T timeout    -- close connection after timeout (default %.3Lf)\n", connectionTimeout);
	printf("  -o offset     -- stagger probes by offset (default %.3Lf)\n", testOffset);
	printf("  -H            -- don't require HMAC\n");
	printf("  -S            -- don't require session sequence numbers\n");
	printf("  -v            -- increase verbose output\n");
	printf("  -h            -- show this help\n");
	printf("\n");
	return rv;
}

int errorBindingAddress(const char *kind, const Address &address)
{
	printf("can't bind %s for %s\n", address.toPresentation().c_str(), kind);
	return 1;
}

}

int main(int argc, char **argv)
{
	int ch;
	Address bindAddress;
	int differentPort = -1;
	Address differentPortBindAddress;
	Address differentAddressBindAddress;
	Address introReplyBindAddress;

	while((ch = getopt(argc, argv, "B:p:a:i:I:m:t:T:o:HSvh")) != -1)
	{
		switch(ch)
		{
		case 'H':
			requireHMAC = false;
			break;

		case 'S':
			requireSSEQ = false;
			break;

		case 'B':
			if(Address::ORIGIN_UNKNOWN != bindAddress.getOrigin())
				return usage(argv[0], 1, "(-B) only specify one listen address", optarg);
			if(not setAddressFromPresentation(optarg, bindAddress))
				return usage(argv[0], 1, "(-B) can't parse listen address: ", optarg);
			break;

		case 'p':
			differentPort = atoi(optarg);
			if((differentPort < 0) or (differentPort > 65535))
				return usage(argv[0], 1, "(-p) port must be between 0 and 65535; you said ", optarg);
			break;

		case 'a':
			if(not setAddressFromPresentation(optarg, differentAddressBindAddress))
				return usage(argv[0], 1, "(-a) can't parse address: ", optarg);
			break;

		case 'i':
			if(not setAddressFromPresentation(optarg, introReplyBindAddress))
				return usage(argv[0], 1, "(-i) can't parse address: ", optarg);
			break;

		case 'I':
			if(not setAddressFromPresentation(optarg, introReplyAddress))
				return usage(argv[0], 1, "(-I) can't parse address: ", optarg);
			break;

		case 'm':
			serverInfo = optarg;
			break;

		case 't':
			tries = atoi(optarg);
			break;

		case 'T':
			connectionTimeout = atof(optarg);
			break;

		case 'o':
			testOffset = atof(optarg);
			break;

		case 'v':
			verbose++;
			break;

		case 'h':
		default:
			return usage(argv[0], 'h' != ch);
		}
	}

	if(Address::ORIGIN_UNKNOWN == bindAddress.getOrigin())
		return usage(argv[0], 1, "-B listen address:port required");

	if(differentPort < 0)
		return usage(argv[0], 1, "-p different port on listen address required");

	differentPortBindAddress = bindAddress;
	differentPortBindAddress.setPort(differentPort);

	if(Address::ORIGIN_UNKNOWN == differentAddressBindAddress.getOrigin())
		return usage(argv[0], 1, "-a different address required");
	if(Address::ORIGIN_UNKNOWN == introReplyBindAddress.getOrigin())
		return usage(argv[0], 1, "-i introduction reply address required");
	if(Address::ORIGIN_UNKNOWN == introReplyAddress.getOrigin())
		introReplyAddress = introReplyBindAddress;

	if(differentAddressBindAddress.getIPAddress() == bindAddress.getIPAddress())
		return usage(argv[0], 1, "error: -a IP address must be different from -B listen address: ", differentAddressBindAddress.toPresentation(false).c_str());

	if(introReplyAddress.getIPAddress() == bindAddress.getIPAddress())
		return usage(argv[0], 1, "error: intro reply IP address must be different from -B listen address: ", introReplyAddress.toPresentation(false).c_str());
	if(introReplyAddress.getIPAddress() == differentAddressBindAddress.getIPAddress())
		return usage(argv[0], 1, "error: intro reply IP address must be different from -a address: ", introReplyAddress.toPresentation(false).c_str());

	if(introReplyBindAddress.getFamily() != introReplyAddress.getFamily())
		printf("warning: public intro reply address isn't in the same family as local intro reply address.\n");

	if((bindAddress.getFamily() != differentAddressBindAddress.getFamily()) or (bindAddress.getFamily() != introReplyAddress.getFamily()))
		printf("warning: addresses are not all in the same family; connectivity check will be inconclusive.\n");

	FlashCryptoAdapter_OpenSSL crypto;
	if(not crypto.init(true, false, nullptr))
	{
		printf("crypto.init error\n");
		return 1;
	}
	crypto.setHMACSendAlways(requireHMAC);
	crypto.setHMACRecvRequired(requireHMAC);
	crypto.setSSeqSendAlways(requireSSEQ);
	crypto.setSSeqRecvRequired(requireSSEQ);
	flashcrypto = &crypto;

	PerformerPosixPlatformAdapter platform(&mainRL, &mainPerformer, &workerPerformer);

	bool rtmfpShutdownComplete = false;
	platform.onShutdownCompleteCallback = [&rtmfpShutdownComplete] { rtmfpShutdownComplete = true; };

	RTMFP rtmfp(&platform, &crypto);
	platform.setRtmfp(&rtmfp);

	rtmfp.setDefaultSessionKeepalivePeriod(10);
	rtmfp.setDefaultSessionRetransmitLimit(20);
	rtmfp.setDefaultSessionIdleLimit(120);

	std::shared_ptr<Address> boundAddr;
	boundAddr = platform.addUdpInterface(bindAddress.getSockaddr());
	if(not boundAddr)
		return errorBindingAddress("listen address", bindAddress);
	printf(",listen,rtmfp,%s\n", boundAddr->toPresentation().c_str());

	rtmfp.onRecvFlow = Client::newClient;

	PosixPlatformAdapter probePlatform(&mainRL);
	NotMeFlashCryptoAdapter probeCrypto;
	if(not probeCrypto.init(false, false, nullptr))
	{
		printf("probeCrypto.init error\n");
		return 1;
	}

	RTMFP probeRtmfp(&probePlatform, &probeCrypto); // impossible to open a session to this RTMFP
	probeRtmfpPtr = &probeRtmfp;
	probePlatform.setRtmfp(probeRtmfpPtr);

	boundAddr = probePlatform.addUdpInterface(differentPortBindAddress.getSockaddr(), &differentPortInterface);
	if(not boundAddr)
		return errorBindingAddress("same address different port", differentPortBindAddress);
	printf(",probe-bind,same-address-different-port,%s\n", boundAddr->toPresentation().c_str());

	boundAddr = probePlatform.addUdpInterface(differentAddressBindAddress.getSockaddr(), &differentAddressInterface);
	if(not boundAddr)
		return errorBindingAddress("different address", differentAddressBindAddress);
	printf(",probe-bind,different-address,%s\n", boundAddr->toPresentation().c_str());

	boundAddr = probePlatform.addUdpInterface(introReplyBindAddress.getSockaddr(), &introReplyInterface);
	if(not boundAddr)
		return errorBindingAddress("introduction reply adddress", introReplyBindAddress);
	printf(",probe-bind,intro-reply-address,%s\n", boundAddr->toPresentation().c_str());

	if(0 == introReplyAddress.getPort())
		introReplyAddress.setPort(boundAddr->getPort());

	printf(",probe-advertise,intro-reply-address,%s\n", introReplyAddress.toPresentation().c_str());

	probeRtmfp.onUnmatchedRHello = Client::onUnmatchedRHello;

	::signal(SIGINT, signal_handler);
	::signal(SIGTERM, signal_handler);

	mainRL.onEveryCycle = [&rtmfp, &rtmfpShutdownComplete] {
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

			stopping = true;

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
