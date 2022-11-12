// Copyright © 2021 Michael Thornburgh
// SPDX-License-Identifier: MIT

#include "../include/rtmfp/TCMessage.hpp"
#include "../include/rtmfp/VLU.hpp"

namespace com { namespace zenomt {

namespace rtmp {

Bytes Message::command(const char *commandName, double transactionID, const AMF0 *commandObject, const uint8_t *payload, size_t len, bool ext)
{
	Bytes rv;

	if(ext)
		rv.push_back(0); // see note at RFC 7425 §5.3.3

	AMF0String(commandName).encode(rv);
	AMF0Number(transactionID).encode(rv);
	if(commandObject)
		commandObject->encode(rv);
	else
		AMF0Null().encode(rv);

	if(payload)
		rv.insert(rv.end(), payload, payload + len);

	return rv;
}

Bytes Message::command(const char *commandName, double transactionID, const AMF0 *commandObject, const Bytes &payload, bool ext)
{
	return command(commandName, transactionID, commandObject, payload.data(), payload.size(), ext);
}

Bytes Message::command(const char *commandName, double transactionID, const AMF0 *commandObject, const AMF0 *infoObject)
{
	return command(commandName, transactionID, commandObject, AMF0::encode(infoObject), false);
}

Bytes Message::command(const char *commandName, double transactionID, const AMF0 *commandObject, const std::shared_ptr<AMF0> &infoObject)
{
	return command(commandName, transactionID, commandObject, infoObject.get());
}

Bytes Message::command(const char *commandName, double transactionID, const std::vector<std::shared_ptr<AMF0>> &args, bool ext)
{
	Bytes rv;

	if(ext)
		rv.push_back(0);

	AMF0String(commandName).encode(rv);
	AMF0Number(transactionID).encode(rv);
	AMF0::encode(args, rv);

	return rv;
}

bool Message::isVideoInit(const uint8_t *payload, size_t len)
{
	return (len > 1) and (TC_VIDEO_CODEC_AVC == (payload[0] & TC_VIDEO_CODEC_MASK)) and (TC_VIDEO_AVCPACKET_AVCC == payload[1]);
}

bool Message::isVideoKeyframe(const uint8_t *payload, size_t len)
{
	return len and (TC_VIDEO_FRAMETYPE_IDR == (payload[0] & TC_VIDEO_FRAMETYPE_MASK));
}

bool Message::isVideoSequenceSpecial(const uint8_t *payload, size_t len)
{
	if(0 == len)
		return true; // "video silence"
	if(len < 2)
		return false;
	return (TC_VIDEO_CODEC_AVC == (payload[0] & TC_VIDEO_CODEC_MASK)) and (TC_VIDEO_AVCPACKET_NALU != payload[1]);
}

bool Message::isAudioInit(const uint8_t *payload, size_t len)
{
	return (len > 1) and (TC_AUDIO_CODEC_AAC == (payload[0] & TC_AUDIO_CODEC_MASK)) and (TC_AUDIO_AACPACKET_AUDIO_SPECIFIC_CONFIG == payload[1]);
}

bool Message::isAudioSequenceSpecial(const uint8_t *payload, size_t len)
{
	return (0 == len) or isAudioInit(payload, len);
}

bool Message::timestamp_lt(uint32_t l, uint32_t r)
{
	return timestamp_gt(r, l);
}

bool Message::timestamp_gt(uint32_t l, uint32_t r)
{
	return (l - r) < UINT32_C(0x80000000);
}

int32_t Message::timestamp_diff(uint32_t l, uint32_t r)
{
	if(timestamp_gt(l, r))
		return int32_t(l - r);
	return 0 - int32_t(r - l);
}

} // namespace rtmp

namespace rtmfp {

using namespace com::zenomt::rtmp;

// --- TCMetadata

size_t TCMetadata::parse(const uint8_t *metadata, const uint8_t *limit, uint32_t *outStreamID, ReceiveOrder *outRxOrder)
{
	if( (limit - metadata < 4) // 'T' 'C' flags vlu
	 or (metadata[0] != 'T')
	 or (metadata[1] != 'C')
	 or (not (metadata[2] & TCMETADATA_FLAG_SID))
	)
		return 0;

	uintmax_t streamID;
	size_t rv = VLU::parse(metadata + 3, limit, &streamID);
	if(0 == rv)
		return 0;

	if(streamID > UINT32_MAX)
		return 0; // impossible RTMP stream ID

	if(outStreamID)
		*outStreamID = (uint32_t)streamID;

	if(outRxOrder)
		*outRxOrder = ((metadata[2] & TCMETADATA_FLAG_RXI_MASK) == TCMETADATA_RXI_NETWORK) ? RO_NETWORK : RO_SEQUENCE;

	return 3 // 'T', 'C', flags
	     + rv; // length of streamID
}

size_t TCMetadata::parse(const Bytes &metadata, uint32_t *outStreamID, ReceiveOrder *outRxOrder)
{
	return parse(metadata.data(), metadata.data() + metadata.size(), outStreamID, outRxOrder);
}

Bytes TCMetadata::encode(uint32_t streamID, ReceiveOrder rxOrder)
{
	Bytes rv;

	rv.push_back('T');
	rv.push_back('C');
	rv.push_back(TCMETADATA_FLAG_SID | ((RO_NETWORK == rxOrder) ? TCMETADATA_RXI_NETWORK : TCMETADATA_RXI_SEQUENCE));
	VLU::append(streamID, rv);

	return rv;
}

// --- TCMessage

size_t TCMessage::parseHeader(const uint8_t *message, const uint8_t *limit, uint8_t *outType, uint32_t *outTimestamp)
{
	const uint8_t *cursor = message;

	if(limit - cursor < 5)
		return 0;

	uint8_t type_ = *cursor++;

	uint32_t timestamp = *cursor++;
	timestamp <<= 8; timestamp += *cursor++;
	timestamp <<= 8; timestamp += *cursor++;
	timestamp <<= 8; timestamp += *cursor++;

	if(outType)
		*outType = type_;
	if(outTimestamp)
		*outTimestamp = timestamp;

	return cursor - message;
}

Bytes TCMessage::message(uint8_t type_, uint32_t timestamp, const uint8_t *msg, size_t len)
{
	Bytes rv;

	rv.push_back(type_);
	rv.push_back((timestamp >> 24) & 0xff);
	rv.push_back((timestamp >> 16) & 0xff);
	rv.push_back((timestamp >>  8) & 0xff);
	rv.push_back((timestamp      ) & 0xff);

	if(msg)
		rv.insert(rv.end(), msg, msg + len);

	return rv;
}

Bytes TCMessage::message(uint8_t type_, uint32_t timestamp, const Bytes &msg)
{
	return message(type_, timestamp, msg.data(), msg.size());
}

Bytes TCMessage::command(const char *commandName, double transactionID, const AMF0 *commandObject, const uint8_t *payload, size_t len, bool ext)
{
	return message(ext ? TCMSG_COMMAND_EX : TCMSG_COMMAND, 0, Message::command(commandName, transactionID, commandObject, payload, len, ext));
}

Bytes TCMessage::command(const char *commandName, double transactionID, const AMF0 *commandObject, const Bytes &payload, bool ext)
{
	return command(commandName, transactionID, commandObject, payload.data(), payload.size(), ext);
}

Bytes TCMessage::command(const char *commandName, double transactionID, const AMF0 *commandObject, const AMF0 *infoObject)
{
	return command(commandName, transactionID, commandObject, AMF0::encode(infoObject), false);
}

Bytes TCMessage::command(const char *commandName, double transactionID, const AMF0 *commandObject, const std::shared_ptr<AMF0> &infoObject)
{
	return command(commandName, transactionID, commandObject, infoObject.get());
}

Bytes TCMessage::command(const char *commandName, double transactionID, const std::vector<std::shared_ptr<rtmp::AMF0>> &args, bool ext)
{
	return message(ext ? TCMSG_COMMAND_EX : TCMSG_COMMAND, 0, Message::command(commandName, transactionID, args, ext));
}

} // namespace rtmfp

} } // namespace com::zenomt
