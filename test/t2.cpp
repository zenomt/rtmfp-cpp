#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>

#include "rtmfp/PosixPlatformAdapter.hpp"
#include "rtmfp/PlainCryptoAdapter.hpp"
#include "rtmfp/RunLoops.hpp"

#include "addrlist.hpp"

using namespace com::zenomt;
using namespace com::zenomt::rtmfp;

static int usage(const char *name, const char *message = nullptr)
{
	if(message)
		printf("%s\n", message);
	printf("usage: %s [-4] [-p port] [-n name] dstname dstaddr port [dstaddr port ...]\n", name);
	return 1;
}

static std::shared_ptr<SendFlow> openFlow(const std::shared_ptr<RTMFP> &rtmfp, const char *dst, Priority pri)
{
	auto flow = rtmfp->openFlow(dst, strlen(dst), "metadata", 8, pri);
	flow->setBufferCapacity(1*1024*1024);
	int count = 0;
	Time lastUpdate = -1;
	flow->onWritable = [flow, pri, count, lastUpdate, &rtmfp] () mutable {

		uint8_t buf[16384] = { 0 };

		count++;
		if(count > 160000)
		{
			flow->close();
			return false;
		}
		auto receipt = flow->write(buf, sizeof(buf), 13);

		Time now = rtmfp->getInstanceAge();
		if((0 == count % 10000) or (now - lastUpdate >= 1.0))
		{
			lastUpdate = now;
			printf("queuing %d:%d at %Lf cwnd:%lu outstanding:%lu buffered:%lu\n", pri, count, now, flow->getCongestionWindow(), flow->getOutstandingBytes(), flow->getBufferedSize());
			receipt->onFinished = [count, pri, flow, &rtmfp] (bool abn) {
				printf("onFinished %d:%d (%d) @%Lf cwnd:%lu outstanding:%lu buffered:%lu\n", pri, count, abn, rtmfp->getInstanceAge(), flow->getCongestionWindow(), flow->getOutstandingBytes(), flow->getBufferedSize());
				fflush(stdout);
			};
		}

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

	if(argc - optind < 3)
		return usage(argv[0], "specify dstname and at least one destaddr port");

	dstName = argv[optind++];
	std::vector<Address> dstAddrs;
	if(not addrlist_parse(argc, argv, optind, false, dstAddrs))
		return 1;

	PreferredRunLoop rl;

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

	auto flow = openFlow(instance, dstName, PRI_ROUTINE);
	add_candidates(flow, dstAddrs);

	rl.scheduleRel(Timer::makeAction([instance] { printf("shutting down\n"); instance->shutdown(true); }), 60, 0);
	rl.run();

	platform.close();
	instance.reset();

	printf("end.\n");

	return 0;
}
