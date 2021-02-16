#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>

#include "rtmfp/PosixPlatformAdapter.hpp"
#include "rtmfp/FlashCryptoAdapter_OpenSSL.hpp"
#include "rtmfp/SelectRunLoop.hpp"
#include "rtmfp/Hex.hpp"
#include "addrlist.hpp"

using namespace com::zenomt;
using namespace com::zenomt::rtmfp;

namespace {

int verbose = 0;

}

static int usage(const char *prog, const char *message, int rv)
{
	if(message)
		printf("%s\n", message);
	printf("usage: %s [options] dstaddr dstport [dstaddr dstport...]\n", prog);
	printf("  -4              -- bind to IPv4 socket (default IPv6)\n");
	printf("  -p port         -- bind to port (default random)\n");
	printf("  -f fingerprint  -- require fingerprint (default any server)\n");
	printf("  -n name         -- required hostname (default any server)\n");
	printf("  -H              -- don't require HMAC\n");
	printf("  -S              -- don't require session sequence numbers\n");
	printf("  -X              -- don't ask for 'any server'\n");
	printf("  -v              -- increase verbose output\n");
	printf("  -h              -- show this help\n");
	return rv;
}

static std::shared_ptr<SendFlow> openFlow(const std::shared_ptr<RTMFP> &rtmfp, const Bytes &epd, Priority pri)
{
	auto flow = rtmfp->openFlow(epd.data(), epd.size(), "metadata", 8, pri);
	flow->onWritable = [flow, pri] {
		uint8_t buf[4096] = { 0 };
		printf("became writable!\n");

		char addr_p[Address::MAX_PRESENTATION_LENGTH] = { 0 };
		flow->getFarAddress().toPresentation(addr_p);
		printf("        addr: %s\n", addr_p);

		auto epd = flow->getFarCanonicalEPD();
		if((epd.size() == 34) and (0x21 == epd[0]) and (0x0f == epd[1]))
			printf("  fingerprint: %s\n", Hex::encode(epd.data() + 2, 32).c_str());
		printf("   near nonce: %s\n", Hex::encode(flow->getNearNonce()).c_str());
		printf("    far nonce: %s\n", Hex::encode(flow->getFarNonce()).c_str());

		for(int count = 0; count < 60; count++)
			flow->write(buf, sizeof(buf), 13)->onFinished = [count, pri, flow] (bool abn) {
				printf("onFinished %d:%d (%d) adv:%lu inflight:%lu\n", pri, count, abn, (unsigned long)flow->getRecvBufferBytesAvailable(), (unsigned long)flow->getOutstandingBytes());
				fflush(stdout);
			};
		flow->close();
		return false;
	};
	flow->notifyWhenWritable();

	flow->onException = [] (uintmax_t reason) { printf("flow exception: %lu\n", reason); };

	return flow;
}

int main(int argc, char * const argv[])
{
	int port = 0;
	int family = AF_INET6;
	const char *uri = "rtmfp:";
	const char *requiredHostname = NULL;
	const char *requiredFingerprint = NULL;
	bool requireHMAC = true;
	bool requireSSEQ = true;
	int ch;

	srand(time(nullptr));

	while((ch = getopt(argc, argv, "4p:f:n:HSXl:vh")) != -1)
	{
		switch(ch)
		{
		case '4':
			family = AF_INET;
			break;
		case 'p':
			port = atoi(optarg);
			break;
		case 'f':
			requiredFingerprint = optarg;
			break;
		case 'n':
			requiredHostname = optarg;
			break;
		case 'H':
			requireHMAC = false;
			break;
		case 'S':
			requireSSEQ = false;
			break;
		case 'X':
			uri = NULL;
			break;
		case 'v':
			verbose++;
			break;
		case 'h':
		default:
			return usage(argv[0], nullptr, 'h' != ch);
		}
	}

	Bytes epd;
	if(not FlashCryptoAdapter::makeEPD(requiredFingerprint, uri, requiredHostname, epd))
	{
		printf("error: bad endpoint discriminator. specify one of fingerprint or hostname if\n");
		printf("  you disable 'any server', and fingerprint must be a valid hexadecimal string.\n");
		return 1;
	}

	if(argc - optind < 2)
		return usage(argv[0], "specify dstaddr dstport", 1);

	std::vector<Address> dstAddrs;
	if(not addrlist_parse(argc, argv, optind, false, dstAddrs))
		return 1;

	SelectRunLoop rl;

	PosixPlatformAdapter platform(&rl);
	platform.onShutdownCompleteCallback = [&rl] { printf("shutdown complete\n"); rl.stop(); };

	FlashCryptoAdapter_OpenSSL crypto;
	crypto.init(false, NULL);
	crypto.setHMACSendAlways(requireHMAC);
	crypto.setHMACRecvRequired(requireHMAC);
	crypto.setSSeqSendAlways(requireSSEQ);
	crypto.setSSeqRecvRequired(requireSSEQ);
	printf("my fingerprint: %s\n", Hex::encode(crypto.getFingerprint()).c_str());

	auto instance = share_ref(new RTMFP(&platform, &crypto), false);
	platform.setRtmfp(instance.get());

	instance->setDefaultSessionKeepalivePeriod(10);
	instance->setDefaultSessionRetransmitLimit(10);
	instance->setDefaultSessionIdleLimit(10);

	auto addr = platform.addUdpInterface(port, family);
	assert(addr);
	printf("got port %d\n", addr->getPort());

	auto flow = openFlow(instance, epd, PRI_ROUTINE);
	add_candidates(flow, dstAddrs);

	openFlow(instance, epd, PRI_PRIORITY);

	rl.scheduleRel(Timer::makeAction([instance] { printf("shutting down\n"); instance->shutdown(true); }), 30, 0);
	rl.run();

	platform.close();
	instance.reset();

	printf("end.\n");

	return 0;
}
