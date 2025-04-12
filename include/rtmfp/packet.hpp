#pragma once

// Copyright © 2021 Michael Thornburgh
// SPDX-License-Identifier: MIT

namespace com { namespace zenomt { namespace rtmfp {

const uint8_t HEADER_FLAG_TC  = 0x80;
const uint8_t HEADER_FLAG_TCR = 0x40;
const uint8_t HEADER_FLAG_TS  = 0x08;
const uint8_t HEADER_FLAG_TSE = 0x04;

const uint8_t HEADER_FLAG_MOD_MASK  = 0x03;
const uint8_t HEADER_MODE_INITIATOR = 0x01;
const uint8_t HEADER_MODE_RESPONDER = 0x02;
const uint8_t HEADER_MODE_STARTUP   = 0x03;

enum {
	CHUNK_FRAGMENT      = 0x7f,

	CHUNK_IHELLO        = 0x30,
	CHUNK_FIHELLO       = 0x0f,
	CHUNK_RHELLO        = 0x70,
	CHUNK_REDIRECT      = 0x71,
	CHUNK_RHELLO_COOKIE_CHANGE = 0x79,
	CHUNK_IIKEYING      = 0x38,
	CHUNK_RIKEYING      = 0x78,

	CHUNK_PING          = 0x01,
	CHUNK_PING_REPLY    = 0x41,

	CHUNK_USERDATA      = 0x10,
	CHUNK_NEXT_USERDATA = 0x11,
	CHUNK_ACK_BITMAP    = 0x50,
	CHUNK_ACK_RANGES    = 0x51,
	CHUNK_BUFFERPROBE   = 0x18,
	CHUNK_EXCEPTION     = 0x5e,

	CHUNK_CLOSE         = 0x0c,
	CHUNK_CLOSE_ACK     = 0x4c,

	// EXPERIMENTAL
	CHUNK_ECN_REPORT    = 0xec
};

const size_t CHUNK_HEADER_LENGTH = 3;
const size_t MAX_RTMFP_HEADER_LENGTH = 5; // flags and both timestamps

const uint8_t USERDATA_FLAG_OPT = 0x80;
const uint8_t USERDATA_FLAG_ABN = 0x02;
const uint8_t USERDATA_FLAG_FIN = 0x01;

const uint8_t USERDATA_FLAG_FRA_MASK = 0x30;
const uint8_t USERDATA_FRA_WHOLE     = 0x00;
const uint8_t USERDATA_FRA_BEGIN     = 0x10;
const uint8_t USERDATA_FRA_END       = 0x20;
const uint8_t USERDATA_FRA_MIDDLE    = 0x30;

enum {
	USERDATA_OPTION_METADATA           = 0x0000,
	USERDATA_OPTION_RETURN_ASSOCIATION = 0x000a,
	USERDATA_OPTION_MANDATORY_CUTOFF   = 0x2000
};

const long double HEADER_TIMESTAMP_SCALE  = 250.0;
const Duration    HEADER_TIMESTAMP_PERIOD = 0.004;

const uint8_t PING_MARKING_MOBILITY = 'M';

} } } // namespace com::zenomt::rtmfp
