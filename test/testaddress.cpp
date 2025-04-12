#include "rtmfp/Address.hpp"

#include <cassert>
#include <cstdio>
#include <cstring>

#include <netdb.h>

using namespace com::zenomt::rtmfp;

uint8_t v4[] = { 127, 0, 0, 1 };
uint8_t v4_v6[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1 };
uint8_t v6[] = { 0x20, 0x01, 0x04, 0x70, 0x81, 0x92, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 };
uint8_t v6_empty[16] = { 0 };

static void _printHex(const uint8_t *buf, size_t len, bool nl=true)
{
	while(len--)
		printf("%02x ", *(buf++));
	if(nl)
		printf("\n");
}

static void _printAddress(const Address& addr)
{
	uint8_t buf[Address::MAX_ENCODED_SIZE];
	char presentation[Address::MAX_PRESENTATION_LENGTH];
	addr.toPresentation(presentation, false);
	printf("%s ", presentation);
	addr.toPresentation(presentation);
	printf("%s ", presentation);
	size_t len = addr.encode(buf);
	printf("(%lu) ", (unsigned long)len);
	_printHex(buf, len);
}

static void _testAddress(const char *src, bool withPort, bool shouldWork)
{
	Address addr;
	printf("testAddress %s %s-port expect-%s", src, withPort ? "with" : "sans", shouldWork ? "pass" : "fail");
	bool result = addr.setFromPresentation(src, withPort);
	printf(" did-%s\n", result ? "pass" : "fail");

	assert(result == shouldWork);
	if(not result)
		return;

	char presentation[Address::MAX_PRESENTATION_LENGTH];
	addr.toPresentation(presentation, withPort);
	printf("  parsed and back: %s\n", presentation);
}

int main(int argc, char *argv[])
{
	if(argc > 1)
	{
		int ai_err = 0;
		auto addrs = Address::lookup(argv[1], "1935", &ai_err);
		if(ai_err)
		{
			printf("err: %d %s\n", ai_err, gai_strerror(ai_err));
			return ai_err;
		}

		for(auto it = addrs.begin(); it != addrs.end(); it++)
			printf("%s\n", it->toPresentation(false).c_str());

		return 0;
	}

	uint8_t dst[Address::MAX_ENCODED_SIZE] = { 0 };
	size_t dstLen;

	Address a1;
	a1.setFamily(AF_INET6);
	a1.setPort(0x1001);
	a1.setOrigin(Address::ORIGIN_REPORTED);

	dstLen = a1.encode(dst);
	assert(19 == dstLen);
	{
		uint8_t expected[19] = { 0x81, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10, 0x01 };
		assert(0 == memcmp(dst, expected, 19));
	}
	_printAddress(a1);

	assert(a1.setFamily(AF_INET));
	memset(dst, 0, sizeof(dst));
	dstLen = a1.encode(dst);
	assert(7 == dstLen);
	{
		uint8_t expected[7] = { 0x01, 0, 0, 0, 0, 0x10, 0x01 };
		assert(0 == memcmp(dst, expected, 7));
	}
	_printAddress(a1);

	assert(a1.setIPAddress(v4, sizeof(v4)));
	memset(dst, 0, sizeof(dst));
	dstLen = a1.encode(dst);
	assert(7 == dstLen);
	{
		uint8_t expected[7] = { 0x01, 127, 0, 0, 1, 0x10, 0x01 };
		assert(0 == memcmp(dst, expected, 7));
	}
	_printAddress(a1);

	assert(a1.setFamily(AF_INET6));
	memset(dst, 0, sizeof(dst));
	dstLen = a1.encode(dst);
	assert(19 == dstLen);
	assert(0x1001 == a1.getPort());
	assert(0 == memcmp(v4_v6, dst + 1, sizeof(v4_v6)));
	_printAddress(a1);

	assert(a1.setFamily(AF_INET));
	memset(dst, 0, sizeof(dst));
	dstLen = a1.encode(dst);
	assert(7 == dstLen);
	{
		uint8_t expected[7] = { 0x01, 127, 0, 0, 1, 0x10, 0x01 };
		assert(0 == memcmp(dst, expected, 7));
	}
	_printAddress(a1);

	Address a2;
	assert(a2.setIPAddress(v6, sizeof(v6)));
	a2.setPort(0x2002);
	a2.setOrigin(Address::ORIGIN_RELAY);
	memset(dst, 0, sizeof(dst));
	dstLen = a2.encode(dst);
	assert(19 == dstLen);
	assert(0x2002 == a2.getPort());
	assert(0 == memcmp(dst+1, v6, sizeof(v6)));
	_printAddress(a2);

	assert(not a2.canMapToFamily(AF_INET));

	a1 = a2;
	assert(0x2002 == a1.getPort());
	assert(AF_INET6 == a1.getFamily());

	Address a3(a2);
	assert(0x2002 == a3.getPort());
	_printAddress(a3);

	Address a4;
	size_t rv = a4.setFromEncoding(dst, dst + sizeof(dst));
	assert(rv == dstLen);
	assert(0x2002 == a4.getPort());
	assert(Address::ORIGIN_RELAY == a4.getOrigin());
	assert(AF_INET6 == a4.getFamily());
	{
		uint8_t dst4[Address::MAX_ENCODED_SIZE];
		size_t dst4Len = a4.encode(dst4);
		assert(dst4Len == dstLen);
		assert(0 == memcmp(dst, dst4, dst4Len));
	}
	_printAddress(a3);

	assert(a2 == a4);
	assert(not (a2 < a4));

	a2.setPort(a4.getPort() - 1);
	assert(a2 < a4);

	_testAddress("2001:470:8192::2", false, true);
	_testAddress("[2001:470:8192::2]", false, true);
	_testAddress("[::127.0.0.1]", false, true);
	_testAddress("[ffff:ffff:FFFF:ffff:ffff:ffff:255.255.255.255]", false, true);
	_testAddress("10.10.10.255", false, true);

	_testAddress("::gh2", false, false);
	_testAddress("1.2.3.4:5678", false, false);
	_testAddress("not an ip address", false, false);

	_testAddress("10.1.1.1:12345", true, true);
	_testAddress("[10.1.2.3]:12345", true, true);
	_testAddress("[::]:54321", true, true);
	_testAddress("[2001::1]:12345", true, true);
	_testAddress("[ffff:ffff:FFFF:ffff:ffff:ffff:255.255.255.255]:55555", true, true);

	_testAddress("[::]", true, false);
	_testAddress("10.1.1.11", true, false);
	_testAddress("not an ip address", true, false);
	_testAddress(":1234", true, false);
	_testAddress("::1234", true, false);
	_testAddress("::12345", true, false);

	printf("Address::lookup(\"localhost\", \"1935\");\n");
	int ai_err = 0;
	auto gai_addresses = Address::lookup("localhost", "1935", &ai_err);
	assert(not gai_addresses.empty());
	assert(0 == ai_err);
	for(auto it = gai_addresses.begin(); it != gai_addresses.end(); it++)
		printf("  %s\n", it->toPresentation().c_str());

	printf("Address::lookup(\"notfound.example.com\", \"1935\"); expect failure\n");
	auto gai_addresses_notfound = Address::lookup("notfound.example.com", "1935", &ai_err);
	assert(gai_addresses_notfound.empty());
	assert(0 != ai_err);
	printf("  returned %d %s\n", ai_err, gai_strerror(ai_err));

	return 0;
}
