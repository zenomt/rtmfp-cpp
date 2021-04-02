#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>

#include "rtmfp/SelectRunLoop.hpp"
#include "rtmfp/FlashCryptoAdapter_OpenSSL.hpp"
#include "rtmfp/PerformerPosixPlatformAdapter.hpp"
#include "rtmfp/Hex.hpp"

using namespace com::zenomt;
using namespace com::zenomt::rtmfp;

namespace {

int verbose = 0;
const char *name = "echo";
int port = 0;
bool requireHMAC = true;
bool requireSSEQ = true;
bool requireHostname = false;
bool interrupted = false;

void signal_handler(int param)
{
	interrupted = true;
}

class Client : public Object {
public:
	~Client()
	{
		if(verbose > 1)
			printf("~Client\n");
	}

	static std::shared_ptr<Client> newClient(std::shared_ptr<RecvFlow> recvFlow)
	{
		auto client = share_ref(new Client(), false);
		client->m_recv = recvFlow;

		Bytes metadata = client->m_recv->getMetadata();
		uint8_t tag[] = { ' ', 'r', 'e', 't', 'u', 'r', 'n' };
		metadata.insert(metadata.end(), tag, tag + sizeof(tag));
		client->m_send = recvFlow->openReturnFlow(metadata);
		client->m_send->onException = [client] (uintmax_t reason) { client->onException(reason); };
		client->m_send->onWritable = [client] { return client->onWritable(); };

		client->m_recv->onMessage = [client] (const uint8_t *bytes, size_t len, uintmax_t sequenceNumber, size_t fragmentCount) { client->onMessage(bytes, len, sequenceNumber, fragmentCount); };
		client->m_recv->onComplete = [client] (bool error) { client->onComplete(error); };

		client->printInfo("new RecvFlow");

		client->m_recv->setBufferCapacity(16*1024*1024);
		client->m_send->setBufferCapacity(2*1024*1024);
		client->m_recv->accept();

		client->m_recv->onFarAddressDidChange = [client] { client->onAddressChanged(); };

		return client;
	}

	void printInfo(const char *msg)
	{
		printf("Client %p: %s\n", (void *)this, msg);
		if(not m_recv)
			return;

		printf("         addr: %s\n", m_recv->getFarAddress().toPresentation().c_str());

		auto epd = m_recv->getFarCanonicalEPD();
		if((epd.size() == 34) and (0x21 == epd[0]) and (0x0f == epd[1]))
			printf("  fingerprint: %s\n", Hex::encode(epd.data() + 2, 32).c_str());
		else
			printf("          EPD: %s\n", Hex::encode(epd.data(), epd.size()).c_str());

		printf("     metadata: %s\n", Hex::encode(m_recv->getMetadata()).c_str());
		printf("   near nonce: %s\n", Hex::encode(m_recv->getNearNonce()).c_str());
		printf("    far nonce: %s\n", Hex::encode(m_recv->getFarNonce()).c_str());

		if(verbose > 1)
			Hex::print("  certificate", m_recv->getFarCertificate());

		printf("\n");
	}

protected:

	bool onWritable()
	{
		if(verbose)
			printf("onWritable, re-enabling receive\n");
		m_recv->setReceiveOrder(RO_SEQUENCE);
		return false;
	}

	void onException(uintmax_t reason)
	{
		printf("exception\n");
		m_recv->setReceiveOrder(RO_SEQUENCE);
		m_send.reset();
	}

	void onMessage(const uint8_t *bytes, size_t len, uintmax_t sequenceNumber, size_t fragmentCount)
	{
		if(m_send)
		{
			m_send->write(bytes, len, 60, 60);
			if(not m_send->isWritable())
			{
				m_recv->setReceiveOrder(RO_HOLD);
				m_send->notifyWhenWritable();
				if(verbose)
					printf("send flow full, suspending receive\n");
			}
		}
		if(verbose)
			printf("onMessage %lu-%lu %lu\n", sequenceNumber, sequenceNumber + fragmentCount - 1, len);
	}

	void onComplete(bool error)
	{
		if(verbose)
			printInfo(error ? "onComplete (error)" : "onComplete");
		else
			printf("Client %p: onComplete%s\n", (void *)this, error ? " (error)" : "");
		if(m_send)
			m_send->close();
		m_send.reset();
		m_recv.reset();
	}

	void onAddressChanged()
	{
		printInfo("far address changed");
	}

	std::shared_ptr<RecvFlow> m_recv;
	std::shared_ptr<SendFlow> m_send;
};

void worker(RunLoop *rl)
{
	printf("starting worker run loop\n");
	rl->run();
	printf("worker run loop and thread end\n");
}

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
	printf("usage: %s (-4 | -6 | -B addr:port) [options]\n", prog);
	printf("  -p port       -- port for -4/-6 (default %d)\n", port);
	printf("  -4            -- bind to IPv4 0.0.0.0:%d\n", port);
	printf("  -6            -- bind to IPv6 [::]:%d\n", port);
	printf("  -B addr:port  -- bind to addr:port explicitly\n");
	printf("  -n name       -- hostname (default %s)\n", name);
	printf("  -N            -- require hostname to connect\n");
	printf("  -H            -- don't require HMAC\n");
	printf("  -S            -- don't require session sequence numbers\n");
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

	srand(time(NULL));

	while((ch = getopt(argc, argv, "vh46B:NHSn:p:")) != -1)
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
		case 'N':
			requireHostname = true;
			break;
		case 'H':
			requireHMAC = false;
			break;
		case 'S':
			requireSSEQ = false;
			break;
		case 'n':
			name = optarg;
			break;
		case 'p':
			port = atoi(optarg);
			break;

		case 'h':
		default:
			return usage(argv[0], NULL, 'h' == ch);
		}
	}

	if(not (bindAddrs.size() or ipv4 or ipv6))
		return usage(argv[0], "specify at least -4, -6, or -B", 1);

	FlashCryptoAdapter_OpenSSL crypto;
	if(not crypto.init(not requireHostname, name))
	{
		printf("crypto.init error\n");
		return 1;
	}
	crypto.setHMACSendAlways(requireHMAC);
	crypto.setHMACRecvRequired(requireHMAC);
	crypto.setSSeqSendAlways(requireSSEQ);
	crypto.setSSeqRecvRequired(requireSSEQ);
	printf("my fingerprint: %s\n", Hex::encode(crypto.getFingerprint()).c_str());
	printf("my name: %s\n", name);

	SelectRunLoop rl;
	Performer performer(&rl);
	SelectRunLoop workerRL;
	Performer workerPerformer(&workerRL);
	PerformerPosixPlatformAdapter platform(&rl, &performer, &workerPerformer);

	RTMFP rtmfp(&platform, &crypto);
	platform.setRtmfp(&rtmfp);

	rtmfp.setDefaultSessionKeepalivePeriod(10);
	rtmfp.setDefaultSessionRetransmitLimit(20);
	rtmfp.setDefaultSessionIdleLimit(300);

	rtmfp.onRecvFlow = Client::newClient;

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

	rl.onEveryCycle = [&rtmfp] { if(interrupted) { interrupted = false; rtmfp.shutdown(true); printf("interrupted. shutting down.\n"); } };
	platform.onShutdownCompleteCallback = [&rl] { rl.stop(); };

	auto workerThread = std::thread(worker, &workerRL);
	rl.run();

	workerPerformer.perform([&workerRL] { workerRL.stop(); });
	workerThread.join();

	printf("end.\n");

	return 0;
}
