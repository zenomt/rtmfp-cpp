#include "rtmfp/Hex.hpp"

#include <cassert>

using namespace com::zenomt;

static void _testHexDecode(const char *hex, int expectedLength)
{
	bool expectPass = expectedLength >= 0;

	printf("Hex parse %s expect-%s len:%d ", hex, expectPass ? "pass" : "fail", expectedLength);

	std::vector<uint8_t> b;
	bool rv = Hex::decode(hex, b);

	printf("did-%s len:%d\n", rv ? "pass" : "fail", (int)b.size());

	assert(rv == expectPass);
	if(expectPass)
		assert((size_t)expectedLength == b.size());

	if(rv)
		printf("  got %s\n", Hex::encode(b.data(), b.size()).c_str());
}

int main(int argc, char *argv[])
{
	uint8_t t1[] = { 0, 1, 5, 4, 5 };
	auto t1_s = Hex::encode(t1, sizeof(t1));
	const char *t1_expected = "0001050405";
	printf("Hex::encode expect '%s' got '%s'\n", t1_expected, t1_s.c_str());
	assert(t1_s == t1_expected);

	_testHexDecode("00 01 02", 3);
	_testHexDecode("00 ff 0102", 4);
	_testHexDecode("", 0);
	_testHexDecode("   f1 ", 1);
	_testHexDecode("   f 1", -1);
	_testHexDecode("   f1 1", -1);
	_testHexDecode("0x33", -1);
	_testHexDecode("fo", -1);
	_testHexDecode("1", -1);

	return 0;
}
