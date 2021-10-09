// Copyright © 2021 Michael Thornburgh
// SPDX-License-Identifier: MIT

// This is a simple sample round-robin load balancer. It accepts registrations
// from RFC 7425 "servers" (endpoints indicating they accept ancillary data in
// their certificates) speaking the http://zenomt.com/ns/rtmfp#redirector protocol.
// This implementation could be used as a starting point for more sophisticated
// redirectors, including asynchronous querying of an external username/password
// database, redirecting to different Clients based on aspects of the incoming
// EPD, and taking the Load Factor into account for better load leveling. With
// minor modifications it could be used as the basis for a P2P introducer (by
// fingerprint).

// TODO: stats
// TODO: shuffle the activeClients for better load leveling
// TODO: only one connection per fingerprint (?)
// TODO: make keyid/password check async for illustration

#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>

#include "rtmfp/SelectRunLoop.hpp"
#include "rtmfp/FlashCryptoAdapter_OpenSSL.hpp"
#include "rtmfp/PerformerPosixPlatformAdapter.hpp"
#include "rtmfp/Hex.hpp"
#include "rtmfp/RedirectorClient.hpp"
#include "rtmfp/VLU.hpp"

using namespace com::zenomt;
using namespace com::zenomt::rtmfp;

namespace {

class Client;

int verbose = 0;
int port = 1935;
int numTargets = 2;
bool interrupted = false;
std::map<Bytes, Bytes> passwords;
Time badAuthDisconnectDelay = 2.0;

SelectRunLoop mainRL;
Performer mainPerformer(&mainRL);
SelectRunLoop workerRL;
Performer workerPerformer(&workerRL);
FlashCryptoAdapter_OpenSSL crypto;
List<std::shared_ptr<Client>> activeClients;
std::set<std::shared_ptr<Client>> clients;

void signal_handler(int param)
{
	interrupted = true;
}

Bytes encodeString(const std::string &str)
{
	return Bytes(str.begin(), str.end());
}

class Client : public Object {
public:
	~Client()
	{
		if(verbose > 1)
			printf("~Client %p\n", (void *)this);
	}

	static void newClient(std::shared_ptr<RecvFlow> recvFlow)
	{
		if(not RedirectorClient::checkFlowMetadata(recvFlow->getMetadata()))
			return;
		Bytes certBytes = recvFlow->getFarCertificate();
		auto cert = crypto.decodeFlashCertificate(certBytes.data(), certBytes.size());
		if((not cert) or not cert->doesAcceptAncillaryData())
			return;

		auto client = share_ref(new Client(), false);
		printf("Client %p connect %s fingerprint %s\n", (void *)client.get(), recvFlow->getFarAddress().toPresentation().c_str(), Hex::encode(cert->getFingerprint()).c_str());

		clients.insert(client);

		client->m_recv = recvFlow;
		recvFlow->onComplete = [client] (bool error) { client->close(); };
		recvFlow->onMessage = [client] (const uint8_t *bytes, size_t len, uintmax_t sequenceNumber, size_t fragmentCount) { client->onMessage(bytes, len); };
		recvFlow->onFarAddressDidChange = [client] { client->onAddressChanged(); };
		recvFlow->accept();

		if(passwords.empty())
			client->m_isAuthenticated = true;
	}

	void close(uintmax_t reason = 0)
	{
		printf("Client %p disconnect", (void *)this);
		if(m_recv)
			printf(" %s", m_recv->getFarAddress().toPresentation().c_str());
		printf("\n");

		retain();

		if(m_send)
			m_send->close();
		m_send.reset();
		if(m_recv)
			m_recv->close(reason);
		m_recv.reset();

		activeClients.remove(m_activeClientsName);
		m_activeClientsName = -1;

		clients.erase(share_ref(this));

		release();
	}

	static void doRedirect(RTMFP *rtmfp, const void *epd, size_t epdLen, const void *tag, size_t tagLen, int interfaceID, const struct sockaddr *srcAddr)
	{
		FlashCryptoAdapter::EPDParseState epdParsed;
		if((not epdParsed.parse((const uint8_t *)epd, epdLen)) or (not epdParsed.ancillaryData) or epdParsed.fingerprint)
			return; // we only know about servers and we don't guarantee forwarding by fingerprint. TODO?

		size_t actualNumTargets = std::min((size_t)numTargets, activeClients.size());

		std::set<Address> usedAddresses;
		std::vector<Address> redirectAddresses; // maintain order of selected clients and each's advertised addresses
		std::vector<std::shared_ptr<Client>> forwardClients;

		while(actualNumTargets-- > 0)
		{
			auto each = activeClients.firstValue();
			activeClients.rotateNameToTail(activeClients.first());

			forwardClients.push_back(each);

			if(each->m_includeReflexiveAddress)
			{
				Address addr = each->m_recv->getFarAddress();
				if(0 == usedAddresses.count(addr))
				{
					redirectAddresses.push_back(addr);
					usedAddresses.insert(addr);
				}
			}
			for(auto it = each->m_additionalAddresses.begin(); it != each->m_additionalAddresses.end(); it++)
			{
				if(0 == usedAddresses.count(*it))
				{
					redirectAddresses.push_back(*it);
					usedAddresses.insert(*it);
				}
			}
		}

		// send redirect before forwards so hopefully outbound holes will be opened by initiator before RHellos arrive
		rtmfp->sendResponderRedirect(tag, tagLen, redirectAddresses, interfaceID, srcAddr);

		for(auto it = forwardClients.begin(); it != forwardClients.end(); it++)
			(*it)->m_recv->forwardIHello(epd, epdLen, Address(srcAddr), tag, tagLen);
	}

protected:
	void delayCloseBadAuth()
	{
		auto myself = share_ref(this);
		
		if(m_recv)
			m_recv->setReceiveOrder(RO_HOLD); // no more messages, but don't close yet

		mainRL.scheduleRel([myself] (const std::shared_ptr<Timer> &sender, Time now) { myself->close(RedirectorClient::EXCEPTION_BAD_AUTH); }, badAuthDisconnectDelay);
	}

	void onMessage(const uint8_t *bytes, size_t len)
	{
		if(verbose > 1) Hex::print("onMessage", bytes, len);
		if(not len)
			return;

		const uint8_t *cursor = bytes;
		const uint8_t *limit = bytes + len;

		uint8_t command = *cursor++;
		if((not m_isAuthenticated) and (RedirectorClient::CMD_SIMPLE_AUTH != command))
		{
			delayCloseBadAuth();
			return;
		}

		switch(command)
		{
		case RedirectorClient::CMD_SIMPLE_AUTH:
			onSimpleAuth(cursor, limit);
			break;
		case RedirectorClient::CMD_SETTINGS:
			onSettings(cursor, limit);
			break;
		case RedirectorClient::CMD_DRAINING:
			onDraining(cursor, limit);
			break;
		case RedirectorClient::CMD_LOAD_FACTOR:
			onLoadFactor(cursor, limit);
			break;
		case RedirectorClient::CMD_USER_DATA:
			onUserData(cursor, limit);
			break;
		default:
			break;
		}
	}

	void onSimpleAuth(const uint8_t *bytes, const uint8_t *limit)
	{
		const uint8_t *cursor = bytes;

		cursor += 32; // skip over hmac
		if(cursor > limit)
			return; // not big enough

		Bytes key(cursor, limit);
		auto it = passwords.find(key);
		if(it == passwords.end())
			return; // ignore keys we don't know

		uint8_t md[32];
		Bytes nonce = m_recv->getNearNonce();
		crypto.hmacSHA256(md, it->second.data(), it->second.size(), nonce.data(), nonce.size());

		if(0 == memcmp(md, bytes, sizeof(md)))
			m_isAuthenticated = true;
		else
			delayCloseBadAuth();
	}

	void onSettings(const uint8_t *bytes, const uint8_t *limit)
	{
		m_includeReflexiveAddress = false;
		m_additionalAddresses.clear();

		const uint8_t *cursor = bytes;
		while(cursor < limit)
		{
			uintmax_t optionType;
			const uint8_t *value;
			size_t valueLen;

			size_t rv = Option::parse(cursor, limit, &optionType, &value, &valueLen);
			if(0 == rv)
			{
				close(); // malformed message
				return;
			}
			cursor += rv;

			if(nullptr == value)
				continue;

			switch(optionType)
			{
			case RedirectorClient::SETTINGS_OPT_INCLUDE_REFLEXIVE:
				if(verbose) printf("Client %p include reflexive\n", (void *)this);
				m_includeReflexiveAddress = true;
				break;

			case RedirectorClient::SETTINGS_OPT_ADD_ADDRESS:
				{
					Address addr;
					if(0 == addr.setFromEncoding(value, value + valueLen))
					{
						close(); // malformed message
						return;
					}
					m_additionalAddresses.push_back(addr);
					if(verbose) printf("Client %p reports address %s\n", (void *)this, addr.toPresentation().c_str());
				}
				break;

			default:
				break;
			}
		}

		if(m_activeClientsName < 0)
			m_activeClientsName = activeClients.prepend(share_ref(this));

		ensureReturnFlow();
	}

	void onDraining(const uint8_t *bytes, const uint8_t *limit)
	{
		activeClients.remove(m_activeClientsName);
		m_activeClientsName = -1;
		ensureReturnFlow();
	}

	void onLoadFactor(const uint8_t *bytes, const uint8_t *limit)
	{
		uintmax_t loadFactor;
		if(0 == VLU::parse(bytes, limit, &loadFactor))
		{
			close(); // malformed message
			return;
		}
		if(verbose) printf("Client %p load factor %lu\n", (void *)this, (unsigned long)loadFactor);

		// maybe do something with this someday

		ensureReturnFlow();
	}

	void onUserData(const uint8_t *bytes, const uint8_t *limit)
	{
		// maybe someday

		ensureReturnFlow();
	}

	void ensureReturnFlow()
	{
		if(m_recv and not m_send)
		{
			m_send = m_recv->openReturnFlow(RedirectorClient::makeFlowMetadata());
			sendReflexiveAddress();
		}
	}

	void onAddressChanged()
	{
		if(verbose)
			printf("Client %p address changed: %s\n", (void *)this, m_recv->getFarAddress().toPresentation().c_str());
		sendReflexiveAddress();
	}

	void sendReflexiveAddress()
	{
		if(m_send)
		{
			Bytes msg;
			msg.push_back(RedirectorClient::CMD_REFLEXIVE_ADDR_REPORT);
			auto addrBytes = m_recv->getFarAddress().encode();
			msg.insert(msg.end(), addrBytes.begin(), addrBytes.end());
			m_send->write(msg);
		}
	}

	long m_activeClientsName { -1 };
	bool m_includeReflexiveAddress { false };
	bool m_isAuthenticated { false };
	std::shared_ptr<SendFlow> m_send;
	std::shared_ptr<RecvFlow> m_recv;
	std::vector<Address> m_additionalAddresses;
};

bool addInterface(PerformerPosixPlatformAdapter *platform, int port, int family)
{
	const char *familyName = (AF_INET6 == family) ? "IPv6" : "IPv4";
	auto addr = platform->addUdpInterface(port, family);
	if(addr)
		printf("bound to %s port %d\n", familyName, addr->getPort());
	else
		printf("error: couldn't bind to %s port %d\n", familyName, port);
	return !!addr;
}

int usage(const char *prog, const char *msg, int rv)
{
	if(msg)
		printf("%s\n", msg);
	printf("usage: %s (-4 | -6 | -B addr:port) -n name [options]\n", prog);
	printf("  -p port       -- port for -4/-6 (default %d)\n", port);
	printf("  -4            -- bind to IPv4 0.0.0.0:%d\n", port);
	printf("  -6            -- bind to IPv6 [::]:%d\n", port);
	printf("  -B addr:port  -- bind to addr:port explicitly\n");
	printf("  -n name       -- hostname\n");
	printf("  -l user:passw -- add username:password\n");
	printf("  -r #targets   -- redirect to #targets (default %d)\n", numTargets);
	printf("  -D #seconds   -- delay before disconnect on bad auth (default %.3fs)\n", (double)badAuthDisconnectDelay);
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
	char *name = nullptr;

	srand(time(NULL));

	while((ch = getopt(argc, argv, "vhp:46B:n:l:r:D:")) != -1)
	{
		switch(ch)
		{
		case 'v':
			verbose++;
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
		case 'n':
			name = optarg;
			break;
		case 'p':
			port = atoi(optarg);
			break;
		case 'l':
			{
				std::string str = optarg;
				auto pos = str.find(':');
				if(std::string::npos == pos)
				{
					printf("can't parse username:password\n");
					return 1;
				}
				passwords[encodeString(str.substr(0, pos))] = encodeString(str.substr(pos + 1));
			}
			break;
		case 'r':
			numTargets = std::max(atoi(optarg), 1);
			break;
		case 'D':
			badAuthDisconnectDelay = atof(optarg);
			break;

		case 'h':
		default:
			return usage(argv[0], NULL, 'h' == ch);
		}
	}

	if(not name)
		return usage(argv[0], "specify a name", 1);

	if(not (bindAddrs.size() or ipv4 or ipv6))
		return usage(argv[0], "specify at least -4, -6, or -B", 1);

	if(not crypto.init(false, name))
	{
		printf("crypto.init error\n");
		return 1;
	}
	crypto.setHMACSendAlways(true);
	crypto.setHMACRecvRequired(true);
	crypto.setSSeqSendAlways(true);
	crypto.setSSeqRecvRequired(true);

	PerformerPosixPlatformAdapter platform(&mainRL, &mainPerformer, &workerPerformer);

	RTMFP rtmfp(&platform, &crypto);
	platform.setRtmfp(&rtmfp);

	rtmfp.setDefaultSessionKeepalivePeriod(15);
	rtmfp.setDefaultSessionRetransmitLimit(15);
	rtmfp.setDefaultSessionIdleLimit(30);

	rtmfp.onRecvFlow = Client::newClient;
	rtmfp.onUnmatchedIHello = [&rtmfp] (const void *epd, size_t epdLen, const void *tag, size_t tagLen, int interfaceID, const struct sockaddr *srcAddr) {
		Client::doRedirect(&rtmfp, epd, epdLen, tag, tagLen, interfaceID, srcAddr);
	};

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

	::signal(SIGINT, signal_handler);
	::signal(SIGTERM, signal_handler);

	bool stopping = false;
	mainRL.onEveryCycle = [&rtmfp, &stopping] {
		if(interrupted)
		{
			interrupted = false;
			rtmfp.shutdown(stopping);
			printf("interrupted. %s\n", stopping ? "quitting." : "shutting down...");
			stopping = true;
		}
	};
	platform.onShutdownCompleteCallback = [] { mainRL.stop(); };

	auto workerThread = std::thread([] { workerRL.run(); });
	mainRL.run();

	workerPerformer.perform([] { workerRL.stop(); });
	workerThread.join();

	printf("end.\n");

	return 0;
}
