#include <cassert>
#include <cstdio>

#include "rtmfp/TCMessage.hpp"
#include "rtmfp/Hex.hpp"

using namespace com::zenomt::rtmfp;
using namespace com::zenomt::rtmp;
using namespace com::zenomt;

int main(int argc, char **argv)
{
	uint8_t md1[] = { 'T', 'C', TCMETADATA_FLAG_SID, 0x81, 0x00 }; // streamID 128
	uint8_t md2[] = { 'T', 'C', TCMETADATA_FLAG_SID | TCMETADATA_RXI_NETWORK, 0x01 }; // streamID 1

	uint8_t md_bad1[] = { 'T', 'C', TCMETADATA_FLAG_SID, 0x81, 0x80 }; // incomplete VLU
	uint8_t md_bad2[] = { 'T', 'C', 0, 0x01 }; // no FLAG_SID

	uint32_t streamID;
	ReceiveOrder rxOrder;

	assert(sizeof(md1) == TCMetadata::parse(md1, md1 + sizeof(md1), &streamID, &rxOrder));
	assert(128 == streamID);
	assert(RO_SEQUENCE == rxOrder);
	printf("md1 got streamID %lu rxorder %d\n", (unsigned long)streamID, rxOrder);

	assert(sizeof(md2) == TCMetadata::parse(md2, md2 + sizeof(md2), &streamID, &rxOrder));
	assert(1 == streamID);
	assert(RO_NETWORK == rxOrder);
	printf("md2 got streamID %lu rxorder %d\n", (unsigned long)streamID, rxOrder);

	assert(0 == TCMetadata::parse(md_bad1, md_bad1 + sizeof(md_bad1), &streamID, &rxOrder));
	assert(0 == TCMetadata::parse(md_bad2, md_bad2 + sizeof(md_bad2), &streamID, &rxOrder));

	Bytes out1 = TCMetadata::encode(12345, RO_SEQUENCE);
	Hex::print("TC streamID 12345 RO_SEQUENCE", out1);
	assert(TCMetadata::parse(out1, &streamID, &rxOrder));
	assert(12345 == streamID);
	assert(RO_SEQUENCE == rxOrder);

	Bytes out2 = TCMetadata::encode(9, RO_NETWORK);
	Hex::print("TC streamID 9 RO_NETWORK", out2);
	assert(TCMetadata::parse(out2, &streamID, &rxOrder));
	assert(9 == streamID);
	assert(RO_NETWORK == rxOrder);

	Bytes tc1 = TCMessage::command("command", 6,
		AMF0::Object()->putValueAtKey(AMF0::String("command value"), "command key"),
		AMF0::Object()->putValueAtKey(AMF0::String("param value"), "param key"));
	Hex::print("TCMessage command", tc1);

	{
		uint8_t t;
		uint32_t ts;
		size_t rv = TCMessage::parseHeader(tc1.data(), tc1.data() + tc1.size(), &t, &ts);
		assert(5 == rv);
		printf("parse TCMessage got type %u timestamp %lu read %lu\n", t, (unsigned long)ts, (unsigned long)rv);
	}

	return 0;
}
