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

class Message {
public:
	// answer AMF message payload suitable for TCMSG_COMMAND (or TCMSG_COMMAND_EX with ext=true)
	static Bytes command(const char *commandName, double transactionID, const AMF0 *commandObject, const uint8_t *payload, size_t len, bool ext = false);
	static Bytes command(const char *commandName, double transactionID, const AMF0 *commandObject, const Bytes &payload, bool ext = false);
	static Bytes command(const char *commandName, double transactionID, const AMF0 *commandObject, const AMF0 *infoObject);
	static Bytes command(const char *commandName, double transactionID, const AMF0 *commandObject, const std::shared_ptr<AMF0> &infoObject);
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
};

} // namespace rtmfp

} } // namespace com::zenomt
