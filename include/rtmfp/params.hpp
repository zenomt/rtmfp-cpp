#pragma once

// Copyright © 2021 Michael Thornburgh
// SPDX-License-Identifier: MIT

namespace com { namespace zenomt { namespace rtmfp {

const size_t DECRYPT_BUF_LENGTH        = 8192;
const size_t ENCRYPT_BUF_LENGTH        = 8192;
const size_t ENCRYPT_BUF_MARGIN        = 16;
const size_t ENCRYPT_BUF_SSID_OFFSET   = 12;
const size_t MAX_STARTUP_PACKET_LENGTH = 4260 - 4;
const size_t MAX_SESSION_PACKET_LENGTH = 1200; // plenty of margin before 1280 for v6 + udp + ssid + encryption
const size_t MAX_PING_MESSAGE_LENGTH   = MAX_SESSION_PACKET_LENGTH - 200;
const size_t MAX_DATA_FRAG_LENGTH      = MAX_SESSION_PACKET_LENGTH - MAX_RTMFP_HEADER_LENGTH - CHUNK_HEADER_LENGTH - 1 - 3 * VLU::MAX_VLU_SIZE;
const size_t MAX_METADATA_LENGTH       = 512;
const Time   ULTIMATE_SESSION_TIMEOUT  = 95.0;
const uintmax_t MAX_COOKIE_LIFETIME    = 95;
const long   MAX_WAITING_PERFORM_COUNT = 16; // might need tuning for busy systems
const size_t REDIRECT_THRESHOLD        = 24;
const size_t IHELLO_TAG_LENGTH         = 16;
const Time   IHELLO_INITIAL_RTX        = 1.000;
const Time   IHELLO_BACKOFF_INTERVAL   = 1.500;
const Time   IIKEYING_INITIAL_RTX      = 1.000;
const Time   IIKEYING_BACKOFF_INTERVAL = 1.500;
const size_t MAX_OPEN_EPD_LENGTH = MAX_STARTUP_PACKET_LENGTH - CHUNK_HEADER_LENGTH - IHELLO_TAG_LENGTH - MAX_RTMFP_HEADER_LENGTH - 1;
const size_t INITIAL_RECV_BUFFER       = 65536;
const size_t INITIAL_SEND_BUFFER       = 65536;
const Time   INITIAL_MRTO              = 0.250;
const Time   INITIAL_ERTO              = 3.000;
const Time   MINIMUM_ERTO              = 0.250;
const Time   DELACK_ALARM_PERIOD       = 0.200;
const Time   ERTO_BACKOFF_FACTOR       = 1.414214; // about √2
const Time   MAX_ERTO                  = 10.0;
const Time   MAX_TS_ECHO_ELAPSED       = 128.0;
const size_t SENDER_MSS                = MAX_DATA_FRAG_LENGTH;
const size_t CWND_INIT                 = 3 * SENDER_MSS;
const size_t CWND_TIMEDOUT             = 2 * SENDER_MSS;
const Time   SAFE_RTT                  = 0.200; // can send CWND_INIT/SAFE_RTT if no path info
const size_t CWND_DECAY_MARGIN         = 6 * SENDER_MSS;
const size_t CWND_DECAY_SIZE           = 1;
const size_t OBLIGATORY_ACK_AFTER      = 2;
const Time   MAX_SEGMENT_LIFETIME      = 120.0;
const Time   RF_COMPLETE_LINGER_PERIOD = MAX_SEGMENT_LIFETIME;
const Time   F_COMPLETE_LINGER_PERIOD  = RF_COMPLETE_LINGER_PERIOD + 10.0;
const Time   F_PERSIST_INITIAL_PERIOD  = 1.0;
const Time   F_PERSIST_BACKOFF_FACTOR  = 1.414214; // about √2
const Time   F_PERSIST_MAX_PERIOD      = 60.0;
const size_t FRAGMENT_SIZE_BIAS        = 64;
const size_t MAX_DATA_PACKET_BURST     = 6; // §3.5.2.3
const long   MAX_DATA_BYTES_BURST      = MAX_DATA_PACKET_BURST * SENDER_MSS;
const Time   BURST_RTT_THRESH          = 0.0045;
const size_t MAX_EARLY_PACKETS         = 18;
const size_t NAKS_FOR_LOSS             = 3;
const Time   TIMECRITICAL_TIMEOUT      = 0.800;
const Time   MIN_KEEPALIVE_PERIOD      = 1.0;
const Time   MIN_RTX_PERIOD            = 1.0;
const Time   MIN_IDLE_PERIOD           = 1.0;
const Time   DEFAULT_KEEPALIVE_PERIOD  = 3600.0; // one hour
const Time   DEFAULT_RTX_LIMIT         = 120.0;
const Time   DEFAULT_IDLE_LIMIT        = 300.0;
const Time   NEARCLOSE_RTX_PERIOD      = 5.0;
const Time   NEARCLOSE_PERIOD          = 90.0;
const Time   FARCLOSE_LINGER_PERIOD    = 19.0;
const uintmax_t MAX_MOBILITY_LIFETIME  = 120;
const uint8_t ECN_CE_DELTA_REORDER     = 0xe0; // allow reordering of up to 32 packets (super unlikely)

} } } // namespace com::zenomt::rtmfp
