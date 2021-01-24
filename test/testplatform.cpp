#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>

#include "rtmfp/PerformerPosixPlatformAdapter.hpp"
#include "rtmfp/PlainCryptoAdapter.hpp"
#include "rtmfp/SelectRunLoop.hpp"
#include "rtmfp/Hex.hpp"

using namespace com::zenomt;
using namespace com::zenomt::rtmfp;

static void worker(RunLoop *rl)
{
	printf("starting worker run loop\n");
	rl->run();
	printf("worker runloop and thread end\n");
}

int main(int argc, char *argv[])
{
	int port = 61555;
	const char *name = "./testplatform";
	int ch;

	while((ch = getopt(argc, argv, "p:n:")) != -1)
	{
		switch(ch)
		{
		case 'p':
			port = atoi(optarg);
			break;
		case 'n':
			name = optarg;
			break;
		default:
			printf("usage: %s [-p port] [-n name]\n", argv[0]);
		}
	}

	SelectRunLoop rl;
	Performer performer(&rl);

	SelectRunLoop workerRL;
	Performer workerPerformer(&workerRL);
	std::thread workerThread = std::thread(worker, &workerRL);

	PerformerPosixPlatformAdapter platform(&rl, &performer, &workerPerformer);
	PlainCryptoAdapter crypto(name);

	RTMFP instance(&platform, &crypto);
	platform.setRtmfp(&instance);

	auto addr = platform.addUdpInterface(port, AF_INET6);
	assert(addr);
	printf("got port %d\n", addr->getPort());

	instance.onRecvFlow = [&rl] (std::shared_ptr<RecvFlow> flow) {
		printf("new incoming flow!\n");
		flow->onMessage = [] (const uint8_t *bytes, size_t len, uintmax_t sequenceNumber, size_t fragmentCount) {
			printf("onMessage %lu %lu\n", sequenceNumber, fragmentCount);
			// Hex::print(" bytes:", bytes, len);
		};
		flow->onComplete = [] (bool error) { printf("flow complete %s\n", error ? "error" : "ok"); };
		// flow->setBufferCapacity(10*1024);
		flow->setBufferCapacity(0);
		// flow->setReceiveOrder(rtmfp::HOLD);
		flow->accept();
		// rl.scheduleRel(3)->action = Timer::makeAction([flow] { printf("rxorder to SEQUENCE\n"); flow->setReceiveOrder(SEQUENCE); });
		rl.scheduleRel(3)->action = Timer::makeAction([flow] { printf("open receive buffer\n"); flow->setBufferCapacity(10*1024); });
	};

	// rl.scheduleRel(Timer::makeAction([] (Time now) { printf("fire %Lf\n", now); }), 0, 1);
	rl.run(150);

	platform.perform(1, [&] { workerRL.stop(); });
	workerThread.join();

	printf("end.\n");

	return 0;
}
