#pragma once

// Copyright © 2021 Michael Thornburgh
// SPDX-License-Identifier: MIT

#include "rtmfp.hpp"
#include "AMF.hpp"

namespace com { namespace zenomt {

namespace rtmp {

using Bytes = std::vector<uint8_t>;

enum {
	TCMSG_SET_CHUNK_SIZE   = 1, // not used with RTMFP
	TCMSG_ABORT_MESSAGE    = 2, // not used with RTMFP
	TCMSG_ACKNOWLEDGEMENT  = 3, // not used with RTMFP
	TCMSG_WINDOW_ACK_SIZE  = 5, // not used with RTMFP
	TCMSG_SET_PEER_BW      = 6, // not used with RTMFP
	TCMSG_USER_CONTROL     = 4,
	TCMSG_COMMAND          = 20,
	TCMSG_COMMAND_EX       = 17,
	TCMSG_DATA             = 18,
	TCMSG_DATA_EX          = 15,
	TCMSG_SHARED_OBJECT    = 19,
	TCMSG_SHARED_OBJECT_EX = 16,
	TCMSG_AUDIO            = 8,
	TCMSG_VIDEO            = 9,
	TCMSG_AGGREGATE        = 22 // should not be used with RTMFP
};

enum {
	TC_USERCONTROL_STREAM_BEGIN = 0,
	TC_USERCONTROL_STREAM_EOF,
	TC_USERCONTROL_STREAM_DRY,
	TC_USERCONTROL_SET_BUFFER_LENGTH,
	TC_USERCONTROL_STREAM_IS_RECORDED,
	TC_USERCONTROL_PING_REQUEST  = 6,  // should not be used with RTMFP
	TC_USERCONTROL_PING_RESPONSE,      // should not be used with RTMFP
	TC_USERCONTROL_FLOW_SYNC     = 34, // RFC 7425 §5.2
	TC_USERCONTROL_SET_KEEPALIVE = 41  // RFC 7425 §5.3.4
};

enum {
	TC_SET_PEER_BW_LIMIT_HARD = 0,
	TC_SET_PEER_BW_LIMIT_SOFT,
	TC_SET_PEER_BW_LIMIT_DYNAMIC
};

enum {
	TC_VIDEO_ENHANCED_FLAG_ISEXHEADER = 8 << 4
};

enum {
	TC_VIDEO_FRAMETYPE_IDR           = 1 << 4,
	TC_VIDEO_FRAMETYPE_INTER         = 2 << 4,
	TC_VIDEO_FRAMETYPE_DISPOSABLE    = 3 << 4,
	TC_VIDEO_FRAMETYPE_GENERATED_IDR = 4 << 4,
	TC_VIDEO_FRAMETYPE_COMMAND       = 5 << 4,
	TC_VIDEO_FRAMETYPE_MASK          = 0x70
};

enum {
	TC_VIDEO_CODEC_NONE      = 0,
	TC_VIDEO_CODEC_SPARK     = 2,
	TC_VIDEO_CODEC_SCREEN    = 3,
	TC_VIDEO_CODEC_VP6       = 4,
	TC_VIDEO_CODEC_VP6_ALPHA = 5,
	TC_VIDEO_CODEC_SCREEN_V2 = 6,
	TC_VIDEO_CODEC_AVC       = 7,
	TC_VIDEO_CODEC_MASK      = 0x0f
};

enum {
	TC_VIDEO_AVCPACKET_AVCC = 0,
	TC_VIDEO_AVCPACKET_NALU = 1,
	TC_VIDEO_AVCPACKET_EOS  = 2
};

enum {
	TC_VIDEO_COMMAND_SEEK_START = 1,
	TC_VIDEO_COMMAND_SEEK_END   = 2
};

enum {
	TC_VIDEO_ENH_PACKETTYPE_SEQUENCE_START         = 0,
	TC_VIDEO_ENH_PACKETTYPE_CODED_FRAMES           = 1,
	TC_VIDEO_ENH_PACKETTYPE_SEQUENCE_END           = 2,
	TC_VIDEO_ENH_PACKETTYPE_CODED_FRAMES_X         = 3,
	TC_VIDEO_ENH_PACKETTYPE_METADATA               = 4,
	TC_VIDEO_ENH_PACKETTYPE_MPEG2TS_SEQUENCE_START = 5,
	TC_VIDEO_ENH_PACKETTYPE_MASK                   = 0x0f
};

enum {
	TC_AUDIO_CODEC_LPCM_PLATFORM    =  0 << 4,
	TC_AUDIO_CODEC_ADPCM            =  1 << 4,
	TC_AUDIO_CODEC_MP3              =  2 << 4,
	TC_AUDIO_CODEC_LPCM_LE          =  3 << 4,
	TC_AUDIO_CODEC_NELLYMOSER_16KHZ =  4 << 4,
	TC_AUDIO_CODEC_NELLYMOSER_8KHZ  =  5 << 4,
	TC_AUDIO_CODEC_NELLYMOSER       =  6 << 4,
	TC_AUDIO_CODEC_G711_A_LAW       =  7 << 4,
	TC_AUDIO_CODEC_G711_MU_LAW      =  8 << 4,
	TC_AUDIO_CODEC_AAC              = 10 << 4,
	TC_AUDIO_CODEC_SPEEX            = 11 << 4,
	TC_AUDIO_CODEC_MP3_8KHZ         = 14 << 4,
	TC_AUDIO_CODEC_DEVICE_SPECIFIC  = 15 << 4,
	TC_AUDIO_CODEC_MASK             = 0xf0
};

enum {
	TC_AUDIO_RATE_5500  = 0 << 2,
	TC_AUDIO_RATE_11025 = 1 << 2,
	TC_AUDIO_RATE_22050 = 2 << 2,
	TC_AUDIO_RATE_44100 = 3 << 2,
	TC_AUDIO_RATE_MASK  = 0x03 << 2
};

enum {
	TC_AUDIO_SOUNDSIZE_8    = 0 << 1,
	TC_AUDIO_SOUNDSIZE_16   = 1 << 1,
	TC_AUDIO_SOUNDSIZE_MASK = 0x01 << 1
};

enum {
	TC_AUDIO_SOUND_MONO   = 0,
	TC_AUDIO_SOUND_STEREO = 1,
	TC_AUDIO_SOUND_MASK   = 0x01
};

enum {
	TC_AUDIO_AACPACKET_AUDIO_SPECIFIC_CONFIG = 0,
	TC_AUDIO_AACPACKET_AUDIO_AAC             = 1
};

class Message {
public:
	// answer AMF message payload suitable for TCMSG_COMMAND (or TCMSG_COMMAND_EX with ext=true)
	static Bytes command(const char *commandName, double transactionID, const AMF0 *commandObject, const uint8_t *payload, size_t len, bool ext = false);
	static Bytes command(const char *commandName, double transactionID, const AMF0 *commandObject, const Bytes &payload, bool ext = false);
	static Bytes command(const char *commandName, double transactionID, const AMF0 *commandObject, const AMF0 *infoObject);
	static Bytes command(const char *commandName, double transactionID, const AMF0 *commandObject, const std::shared_ptr<AMF0> &infoObject);
	static Bytes command(const char *commandName, double transactionID, const std::vector<std::shared_ptr<AMF0>> &args, bool ext = false);

	static bool isVideoInit(const uint8_t *payload, size_t len);
	static bool isVideoKeyframe(const uint8_t *payload, size_t len);
	static bool isVideoSequenceSpecial(const uint8_t *payload, size_t len);

	// "Enhanced RTMP" see https://github.com/veovera/enhanced-rtmp
	static bool isVideoEnhanced(const uint8_t *payload, size_t len);
	static bool isVideoEnhancedMetadata(const uint8_t *payload, size_t len);

	static bool isAudioInit(const uint8_t *payload, size_t len);
	static bool isAudioSequenceSpecial(const uint8_t *payload, size_t len);

	// answer true if l is before r with wrap-around.
	static bool timestamp_lt(uint32_t l, uint32_t r);

	// answer true if l is after r with wrap-around.
	static bool timestamp_gt(uint32_t l, uint32_t r);

	// answer l - r. timestamps are considered to be within 2^31-1 of each other.
	static int32_t timestamp_diff(uint32_t l, uint32_t r);
};

} // namespace rtmp

namespace rtmfp {

const uint8_t TCMETADATA_FLAG_SID = 0x04; // Stream ID Present, required
const uint8_t TCMETADATA_FLAG_RXI_MASK = 0x01; // Receive Intent

enum {
	TCMETADATA_RXI_SEQUENCE = 0,
	TCMETADATA_RXI_NETWORK = 1
};

class TCMetadata {
public:
	static size_t parse(const uint8_t *metadata, const uint8_t *limit, uint32_t *outStreamID, ReceiveOrder *outRxOrder);
	static size_t parse(const Bytes &metadata, uint32_t *outStreamID, ReceiveOrder *outRxOrder);

	static Bytes encode(uint32_t streamID, ReceiveOrder rxOrder);
};

class TCMessage {
public:
	static size_t parseHeader(const uint8_t *message, const uint8_t *limit, uint8_t *outType, uint32_t *outTimestamp);

	static Bytes message(uint8_t type_, uint32_t timestamp, const uint8_t *msg, size_t len);
	static Bytes message(uint8_t type_, uint32_t timestamp, const Bytes &msg);

	// answer TCMessages of type TCMSG_COMMAND (or TCMSG_COMMAND_EX if ext=true) and timestamp 0
	static Bytes command(const char *commandName, double transactionID, const rtmp::AMF0 *commandObject, const uint8_t *payload, size_t len, bool ext = false);
	static Bytes command(const char *commandName, double transactionID, const rtmp::AMF0 *commandObject, const Bytes &payload, bool ext = false);
	static Bytes command(const char *commandName, double transactionID, const rtmp::AMF0 *commandObject, const rtmp::AMF0 *infoObject);
	static Bytes command(const char *commandName, double transactionID, const rtmp::AMF0 *commandObject, const std::shared_ptr<rtmp::AMF0> &infoObject);
	static Bytes command(const char *commandName, double transactionID, const std::vector<std::shared_ptr<rtmp::AMF0>> &args, bool ext = false);
};

} // namespace rtmfp

} } // namespace com::zenomt
