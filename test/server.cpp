#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>

#include "rtmfp/PosixPlatformAdapter.hpp"
#include "rtmfp/PlainCryptoAdapter.hpp"
#include "rtmfp/SelectRunLoop.hpp"
#include "rtmfp/Hex.hpp"

using namespace com::zenomt;
using namespace com::zenomt::rtmfp;

static int usage(const char *name, const char *message = nullptr)
{
	if(message)
		printf("%s\n", message);
	printf("usage: %s (-4|-6) -p port [-n name]\n", name);
	return 1;
}

int main(int argc, char *argv[])
{
	int port = 0;
	const char *name = "server";
	int family = 0;
	int ch;

	while((ch = getopt(argc, argv, "h46p:n:")) != -1)
	{
		switch(ch)
		{
		case '4':
			family = AF_INET;
			break;
		case '6':
			family = AF_INET6;
			break;
		case 'p':
			port = atoi(optarg);
			break;
		case 'n':
			name = optarg;
			break;
		case 'h':
		default:
			return usage(argv[0]);
		}
	}

	if(not family)
		return usage(argv[0], "specify family -4 or -6");
	if(not port)
		return usage(argv[0], "specify port");

	SelectRunLoop rl;

	PosixPlatformAdapter platform(&rl);
	PlainCryptoAdapter crypto(name);

	RTMFP instance(&platform, &crypto);
	platform.setRtmfp(&instance);

	auto addr = platform.addUdpInterface(port, family);
	assert(addr);
	printf("got port %d\n", addr->getPort());

	instance.onRecvFlow = [&rl] (std::shared_ptr<RecvFlow> flow) {
		printf("new incoming flow!\n");
		printf("RTT: %Lf\n", flow->getSRTT());
		flow->onMessage = [] (const uint8_t *bytes, size_t len, uintmax_t sequenceNumber, size_t fragmentCount) {
			printf("onMessage sn:%lu frags:%lu size:%lu\n", sequenceNumber, fragmentCount, len);
			// Hex::print(" bytes:", bytes, len);
		};
		flow->onComplete = [] (bool error) { printf("flow complete %s\n", error ? "error" : "ok"); };
		// flow->setBufferCapacity(10*1024);
		flow->setBufferCapacity(0);
		// flow->setReceiveOrder(RO_NETWORK);
		flow->setReceiveOrder(RO_SEQUENCE);
		flow->onFarAddressDidChange = [] { printf("far address change detected (RecvFlow)\n"); };
		flow->accept();
		// rl.scheduleRel(3)->action = Timer::makeAction([flow] { printf("rxorder to SEQUENCE\n"); flow->setReceiveOrder(SEQUENCE); });
		rl.scheduleRel(3)->action = Timer::makeAction([flow] { printf("open receive buffer\n"); flow->setBufferCapacity(64*1024); });
		// rl.scheduleRel(10)->action = Timer::makeAction([flow] { flow->close(3); });

		// auto returnFlow = flow->openReturnFlow("return", 6);
		// returnFlow->onFarAddressDidChange = [] { printf("far address change detected (SendFlow)\n"); };
	};

	instance.onUnmatchedIHello = [] (const void *epd, size_t epdLen, const void *tag, size_t tagLen, int interfaceID, const struct sockaddr *srcAddr) {
		Hex::print("onUnmatchedIHello", epd, epdLen);
		Address a(srcAddr);
		Bytes a_encoded = a.encode();
		Hex::dump("address: ", a_encoded.data(), a_encoded.size());
	};

	instance.setDefaultSessionKeepalivePeriod(10);
	instance.setDefaultSessionRetransmitLimit(30);
	instance.setDefaultSessionIdleLimit(5);

	rl.run();

	printf("end.\n");

	return 0;
}
