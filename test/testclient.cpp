#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>

#include "rtmfp/PosixPlatformAdapter.hpp"
#include "rtmfp/PlainCryptoAdapter.hpp"
#include "rtmfp/SelectRunLoop.hpp"
#include "addrlist.hpp"

using namespace com::zenomt;
using namespace com::zenomt::rtmfp;

namespace {

class LossyPlatformAdapter : public PosixPlatformAdapter {
public:
	LossyPlatformAdapter(RunLoop *runloop) :
		PosixPlatformAdapter(runloop),
		m_thresh(0)
	{}

	bool writePacket(const void *bytes, size_t len, int interfaceID, const struct sockaddr *addr, socklen_t addrLen) override
	{
		if((rand() % 10000) < m_thresh)
			len = 0;

		return PosixPlatformAdapter::writePacket(bytes, len, interfaceID, addr, addrLen);
	}

	void setThresh(double thresh)
	{
		m_thresh = thresh * 10000;
	}

	int m_thresh;
};

}

static int usage(const char *name, const char *message = nullptr)
{
	if(message)
		printf("%s\n", message);
	printf("usage: %s [-4] [-p port] [-n name] [-l lossrate] dstname dstaddr dstport [dstaddr dstport...]\n", name);
	return 1;
}

static std::shared_ptr<SendFlow> openFlow(const std::shared_ptr<RTMFP> &rtmfp, const char *dst, Priority pri)
{
	auto flow = rtmfp->openFlow(dst, strlen(dst), "metadata", 8, pri);
	flow->onWritable = [flow, pri] {
		uint8_t buf[4096] = { 0 };
		printf("became writable!\n");

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
	const char *name = argv[0];
	const char *dstName;
	int ch;
	double thresh = 0;

	srand(time(nullptr));

	while((ch = getopt(argc, argv, "h4p:n:l:")) != -1)
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
		case 'l':
			thresh = atof(optarg);
			break;
		case 'h':
		default:
			return usage(argv[0]);
		}
	}

	if(argc - optind < 3)
		return usage(argv[0], "specify dstname dstaddr dstport");

	dstName = argv[optind++];
	std::vector<Address> dstAddrs;
	if(not addrlist_parse(argc, argv, optind, false, dstAddrs))
		return 1;

	SelectRunLoop rl;

	LossyPlatformAdapter platform(&rl);
	platform.setThresh(thresh);
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

	openFlow(instance, dstName, PRI_PRIORITY);

	// rl.scheduleRel(Timer::makeAction([] (Time now) { printf("fire %Lf\n", now); }), 0, 1);
	rl.scheduleRel(Timer::makeAction([instance] { printf("shutting down\n"); instance->shutdown(true); }), 30, 0);
	rl.run();

	platform.close();
	instance.reset();

	printf("end.\n");

	return 0;
}
