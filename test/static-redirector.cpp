#include <cstdio>
#include <cstdlib>
#include <unistd.h>

#include "rtmfp/RunLoops.hpp"
#include "rtmfp/PosixPlatformAdapter.hpp"
#include "rtmfp/FlashCryptoAdapter_OpenSSL.hpp"

using namespace com::zenomt;
using namespace com::zenomt::rtmfp;

namespace {

int verbose = 0;
int port = 0;

bool addrlist_parse(int argc, char * const *argv, int start_at, bool combined, List<Address> &dst)
{
	int parts = combined ? 1 : 2;

	while(start_at < argc - parts + 1)
	{
		Address each;
		if(not each.setFromPresentation(argv[start_at], combined))
		{
			printf("can't parse address: %s\n", argv[start_at]);
			return false;
		}
		if(not combined)
			each.setPort(atoi(argv[start_at + 1]));
		dst.append(each);
		start_at += parts;
	}

	return true;
}

std::vector<Address> toVector(List<Address> &addrs)
{
	std::vector<Address> rv;
	addrs.valuesDo([&rv] (Address &each) { rv.push_back(each); return true; });
	return rv;
}

class NotMeFlashCryptoAdapter : public FlashCryptoAdapter_OpenSSL {
public:
	bool isSelectedByEPD(const uint8_t *epd, size_t epdLen) override
	{
		return false;
	}
};

bool addInterface(PosixPlatformAdapter *platform, int port, int family)
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
	printf("usage: %s (-4 | -6 | -B addr:port) [options] dstaddr:port [dstaddr:port ...]\n", prog);
	printf("  -p port       -- port for -4/-6 (default %d)\n", port);
	printf("  -4            -- bind to IPv4 0.0.0.0:%d\n", port);
	printf("  -6            -- bind to IPv6 [::]:%d\n", port);
	printf("  -B addr:port  -- bind to addr:port explicitly\n");
	printf("  -r            -- rotate redirect addresses on each redirect\n");
	printf("  -v            -- increase verbose output\n");
	printf("  -h            -- show this help\n");
	printf("\n");
	printf("  dstaddr:port  -- redirect initiators to dstaddr:port\n");
	return rv;
}

}

int main(int argc, char **argv)
{
	bool ipv4 = false;
	bool ipv6 = false;
	bool rotate = false;
	std::vector<Address> bindAddrs;
	List<Address> redirectAddrs;
	int ch;

	srand(time(NULL));

	while((ch = getopt(argc, argv, "vh46B:p:r")) != -1)
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
		case 'p':
			port = atoi(optarg);
			break;
		case 'r':
			rotate = true;
			break;

		case 'h':
		default:
			return usage(argv[0], NULL, 'h' == ch);
		}
	}

	if(not (bindAddrs.size() or ipv4 or ipv6))
		return usage(argv[0], "specify at least -4, -6, or -B", 1);

	if(not addrlist_parse(argc, argv, optind, true, redirectAddrs))
		return 1;
	if(redirectAddrs.empty())
		return usage(argv[0], "specify at least one redirect address", 1);

	NotMeFlashCryptoAdapter crypto;
	if(not crypto.init(false, nullptr))
	{
		printf("crypto.init error\n");
		return 1;
	}

	PreferredRunLoop rl;
	PosixPlatformAdapter platform(&rl);

	RTMFP rtmfp(&platform, &crypto);
	platform.setRtmfp(&rtmfp);

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

	rtmfp.onUnmatchedIHello = [&] (const void *epd, size_t epdLen, const void *tag, size_t tagLen, int interfaceID, const struct sockaddr *srcAddr) {
		if(verbose)
			printf("IHello from %s\n", Address(srcAddr).toPresentation().c_str());
		rtmfp.sendResponderRedirect(tag, tagLen, toVector(redirectAddrs), interfaceID, srcAddr);
		if(rotate)
			redirectAddrs.rotateNameToTail(redirectAddrs.first());
	};

	rl.run();

	// NOTREACHED
	printf("end.\n");

	return 0;
}
