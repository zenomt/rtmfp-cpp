#include "rtmfp/Address.hpp"

#include <cassert>
#include <cstring>

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
	size_t len = addr.encode(buf);
	printf("(%lu) ", (unsigned long)len);
	_printHex(buf, len);
}

int main(int argc, char *argv[])
{
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

	return 0;
}
