#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>

#include "rtmfp/PosixPlatformAdapter.hpp"
#include "rtmfp/PlainCryptoAdapter.hpp"
#include "rtmfp/SelectRunLoop.hpp"

using namespace com::zenomt;
using namespace com::zenomt::rtmfp;

static int usage(const char *name, const char *message = nullptr)
{
	if(message)
		printf("%s\n", message);
	printf("usage: %s [-4] [-p port] [-n name] dstname dstport\n", name);
	return 1;
}

static std::shared_ptr<SendFlow> openFlow(const std::shared_ptr<RTMFP> &rtmfp, const char *dst, Priority pri)
{
	auto flow = rtmfp->openFlow(dst, strlen(dst), "metadata", 8, pri);
	int count = 0;
	flow->onWritable = [flow, pri, count, &rtmfp] () mutable {
		uint8_t buf[16384] = { 0 };

		count++;
		if(count > 160000)
		{
			flow->close();
			return false;
		}
		auto receipt = flow->write(buf, sizeof(buf), 13);

		if(0 == count % 10000)
			receipt->onFinished = [count, pri, &rtmfp] (bool abn) { printf("onFinished %d:%d (%d) @%Lf\n", pri, count, abn, rtmfp->getInstanceAge()); fflush(stdout); };

		return true;
	};
	flow->notifyWhenWritable();

	flow->onException = [] (uintmax_t reason) { printf("flow exception: %lu\n", reason); };

	return flow;
}

int main(int argc, char *argv[])
{
	int port = 0;
	int family = AF_INET6;
	const char *name = argv[0];
	const char *dstName;
	int dstPort;
	int ch;

	srand(time(nullptr));

	while((ch = getopt(argc, argv, "h4p:n:")) != -1)
	{
		switch(ch)
		{
		case '4':
			family = AF_INET;
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

	if(argc - optind < 2)
		return usage(argv[0], "specify dstname and dstport");

	dstName = argv[optind];
	dstPort = atoi(argv[optind + 1]);

	SelectRunLoop rl;

	PosixPlatformAdapter platform(&rl);
	platform.onShutdownCompleteCallback = [&rl] { printf("shutdown complete\n"); rl.stop(); };

	PlainCryptoAdapter crypto(name);

	auto instance = share_ref(new RTMFP(&platform, &crypto), false);
	platform.setRtmfp(instance.get());

	instance->setDefaultSessionKeepalivePeriod(10);
	instance->setDefaultSessionRetransmitLimit(10);
	instance->setDefaultSessionIdleLimit(10);

	auto addr = platform.addUdpInterface(port, family);
	assert(addr);
	printf("got port %d\n", addr->getPort());

	uint8_t dst_ip[] = { 127, 0, 0, 1 };
	Address dst;
	dst.setIPAddress(dst_ip, sizeof(dst_ip));
	dst.setPort(dstPort);
	
	openFlow(instance, dstName, PRI_ROUTINE)->addCandidateAddress(dst);

	// rl.scheduleRel(Timer::makeAction([] (Time now) { printf("fire %Lf\n", now); }), 0, 1);
	rl.scheduleRel(Timer::makeAction([instance] { printf("shutting down\n"); instance->shutdown(true); }), 30, 0);
	rl.run();

	platform.close();
	instance.reset();

	printf("end.\n");

	return 0;
}
