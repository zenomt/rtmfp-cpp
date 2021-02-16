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

		char addr_p[Address::MAX_PRESENTATION_LENGTH] = { 0 };
		m_recv->getFarAddress().toPresentation(addr_p);
		printf("        addr: %s\n", addr_p);

		auto epd = m_recv->getFarCanonicalEPD();
		if((epd.size() == 34) and (0x21 == epd[0]) and (0x0f == epd[1]))
			printf("  fingerprint: %s\n", Hex::encode(epd.data() + 2, 32).c_str());
		else
			printf("          EPD: %s\n", Hex::encode(m_recv->getFarCanonicalEPD()).c_str());
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

int usage(const char *prog, const char *msg, int rv)
{
	if(msg)
		printf("%s\n", msg);
	printf("usage: %s [options]\n", prog);
	printf("  -4       -- bind to IPv4 socket (default IPv6)\n");
	printf("  -p port  -- bind to port (default %d)\n", port);
	printf("  -n name  -- hostname (default %s)\n", name);
	printf("  -N       -- require hostname to connect\n");
	printf("  -H       -- don't require HMAC\n");
	printf("  -S       -- don't require session sequence numbers\n");
	printf("  -v       -- increase verbose output\n");
	printf("  -h       -- show this help\n");
	return rv;
}

}

int main(int argc, char **argv)
{
	int family = AF_INET6;
	int ch;

	srand(time(NULL));

	while((ch = getopt(argc, argv, "vh4NHSn:p:")) != -1)
	{
		switch(ch)
		{
		case 'v':
			verbose++;
			break;
		case '4':
			family = AF_INET;
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

	SelectRunLoop rl;
	Performer performer(&rl);
	SelectRunLoop workerRL;
	Performer workerPerformer(&workerRL);
	auto workerThread = std::thread(worker, &workerRL);

	PerformerPosixPlatformAdapter platform(&rl, &performer, &workerPerformer);

	RTMFP rtmfp(&platform, &crypto);
	platform.setRtmfp(&rtmfp);

	rtmfp.setDefaultSessionKeepalivePeriod(10);
	rtmfp.setDefaultSessionRetransmitLimit(20);
	rtmfp.setDefaultSessionIdleLimit(300);

	rtmfp.onRecvFlow = Client::newClient;

	auto addr = platform.addUdpInterface(port, family);
	if(addr)
	{
		printf("listening on port %d\n", addr->getPort());
		rl.run();
	}
	else
	{
		printf("error: couldn't bind to port %d\n", port);
		workerPerformer.perform([&workerRL] { workerRL.stop(); });
	}

	workerThread.join();

	return 0;
}