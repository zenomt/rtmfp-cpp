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

	assert(Message::timestamp_lt(1, 2));
	assert(Message::timestamp_lt(UINT32_C(0x90000000), UINT32_C(0xa0000000)));
	assert(Message::timestamp_lt(UINT32_C(0xF0000000), 0));
	assert(Message::timestamp_lt(UINT32_C(0xF0000000), 1));
	assert(Message::timestamp_lt(UINT32_C(0xF0000000), UINT32_C(0x60000000)));
	assert(not Message::timestamp_lt(2, 1));
	assert(Message::timestamp_gt(2, 1));

	assert(1 == Message::timestamp_diff(2, 1));
	assert(-1 == Message::timestamp_diff(1, 2));
	assert(-101 == Message::timestamp_diff(uint32_t(0) - uint32_t(100), 1));
	assert(1 == Message::timestamp_diff(UINT32_C(0xF0000005), UINT32_C(0xF0000004)));
	assert(-1 == Message::timestamp_diff(UINT32_C(0xF0000004), UINT32_C(0xF0000005)));

	uint8_t v1[] = { TC_VIDEO_FRAMETYPE_IDR | TC_VIDEO_CODEC_AVC, TC_VIDEO_AVCPACKET_NALU, 0, 0, 0 };
	assert(TC_VIDEO_CODEC_AVC == Message::getVideoCodec(v1, sizeof(v1)));

	uint8_t v2[] = { TC_VIDEO_ENHANCED_FLAG_ISEXHEADER | TC_VIDEO_FRAMETYPE_IDR | TC_VIDEO_ENH_PACKETTYPE_CODED_FRAMES, 0x68, 0x76, 0x63, 0x31, 0, 0, 0 };
	assert(TC_VIDEO_ENH_CODEC_HEVC == Message::getVideoCodec(v2, sizeof(v2)));

	uint8_t a1[] = { TC_AUDIO_CODEC_AAC | TC_AUDIO_RATE_44100 | TC_AUDIO_SOUNDSIZE_16 | TC_AUDIO_SOUND_STEREO, TC_AUDIO_AACPACKET_AUDIO_AAC };
	assert(TC_AUDIO_CODEC_AAC == Message::getAudioCodec(a1, sizeof(a1)));

	return 0;
}
