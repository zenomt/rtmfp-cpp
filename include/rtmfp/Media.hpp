#pragma once

// Copyright © 2021 Michael Thornburgh
// SPDX-License-Identifier: MIT

// Helpers for http://zenomt.com/ns/rtmfp#media media flows:
// a flow type, including metadata and message encapsulation
// formats, for general-purpose real-time media streams in RTMFP
// beyond Flash Media.

#include "rtmfp.hpp"

namespace com { namespace zenomt { namespace rtmfp {

class Media : public Object {
public:
	static constexpr uintmax_t DEFAULT_TIMESCALE_TICKS = 1000;
	static constexpr uintmax_t DEFAULT_TIMESCALE_PER_SECONDS = 1;

	Media() = default;
	Media(const Media &other);

	static std::shared_ptr<Media> fromMetadata(const Bytes &metadata);

	size_t setFromMetadata(const Bytes &metadata); // receiver should be in initialized state
	Bytes  toMetadata() const;

	uintmax_t   streamID { 0 };
	std::string codec;
	std::string trackName;
	Time        reorderSuggestion { -1.0 }; // < 0 means no suggestion

	void      setTrackID(uintmax_t trackID);
	uintmax_t getTrackID() const;
	void      clearTrackID();
	bool      hasTrackID() const;

	bool setOrigin(Time origin); // origin must be non-negative and finite
	Time getOrigin() const;
	bool setTimescale(uintmax_t ticks, uintmax_t perSeconds);
	void getTimescale(uintmax_t *ticks, uintmax_t *perSeconds) const;
	Time getTickDuration() const;

	bool         setReceiveIntent(ReceiveOrder intent); // hint must be RO_SEQUENCE or RO_NETWORK
	ReceiveOrder getReceiveIntent() const;

	static Bytes basicMakeMessage(bool rai, int messageType, uintmax_t dtsTicks, uintmax_t ptsTicks, const void *optionList, size_t optionListLen, const void *payload, size_t len);

	Bytes makeMessage(bool rai, int messageType, Time dts, Time pts, const void *optionList, size_t optionListLen, const void *payload, size_t len) const;
	Bytes makeMessage(bool rai, int messageType, Time dts, Time pts, const void *payload, size_t len) const;
	Bytes makeMessage(bool rai, int messageType, Time dts, Time pts, const Bytes &optionList, const Bytes &payload) const;
	Bytes makeMessage(bool rai, int messageType, Time dts, Time pts, const Bytes &payload) const;

	// Answers byte offset where payload begins, or 0 on error. If there are no options,
	// outOptionListOffset will be the same as the return value (indicating the option
	// list is 0-length, only possible with no option list at all).
	static size_t basicParseHeader(const uint8_t *message, size_t len, bool *outRAI, int *outMessageType, uintmax_t *outDTSTicks, uintmax_t *outPTSTicks, size_t *outOptionListOffset);
	size_t parseHeader(const uint8_t *message, size_t len, bool *outRAI, int *outMessageType, Time *outDTS, Time *outPTS, size_t *outOptionListOffset) const;

	Time      ticksToTime(uintmax_t ticks) const;
	uintmax_t timeToTicks(Time t) const;

	static constexpr uint8_t FLAG_RAI = 0x80;
	static constexpr uint8_t FLAG_OPT = 0x40;

	enum {
		MSG_MEDIA                    = 1,
		MSG_RANDOM_ACCESS_CHECKPOINT = 5,
		MSG_TIMING_CHECKPOINT        = 6,
		MSG_SILENCE                  = 7,
		MSG_SEQUENCE_HEADER          = 9,
		MSG_FLOW_SYNC                = 15,
		MSG_MASK                     = 0x0f
	};

	enum {
		TSS_NONE             = 0 << 4,
		TSS_DTS              = 1 << 4,
		TSS_DTS_PLUS_OFFSET  = 2 << 4,
		TSS_DTS_MINUS_OFFSET = 3 << 4,
		TSS_MASK             = 3 << 4
	};

	enum {
		OPTION_STREAM_ID              = 0x1d,
		OPTION_CODEC                  = 0x4c,
		OPTION_TIME_ORIGIN            = 0x00,
		OPTION_TIMESCALE              = 0x01,
		OPTION_RECEIVE_INTENT_NETWORK = 0x0a,
		OPTION_REORDER_SUGGESTION     = 0x0b,
		OPTION_TRACK_NAME             = 0x21,
		OPTION_TRACK_ID               = 0x2d
	};

protected:
	Time         m_origin { 0.0 };
	uintmax_t    m_timescale_ticks { DEFAULT_TIMESCALE_TICKS };
	uintmax_t    m_timescale_perSeconds { DEFAULT_TIMESCALE_PER_SECONDS };
	ReceiveOrder m_receiveIntent { RO_SEQUENCE };
	uintmax_t    m_trackID { 0 };
	bool         m_hasTrackID { false };
};

/*

metadata format: 'http://zenomt.com/ns/rtmfp#media' <00> [options...]
  options:
    1d stream id: <vlu> (required)
    4c codec: <utf-8 ...> (required, usually fourcc, more as needed, see RFC 6381 & https://mp4ra.org/#/codecs)
    00 time origin: <128-bit NTPv4 timestamp> (default 0, era must be non-negative)
    01 timescale: <vlu ticks> <vlu per-seconds> (default 1000/1s, both must be nonzero)
    0a receive intent = network arrival order (if not present, intent = original queuing order)
    0b suggested reorder buffer duration <vlu ticks> (default no recommendation)
    21 track name: <utf-8 ...> (default none/auto, should be short <= 64 bytes, in track's primary language)
    2d track id: <vlu> (default none (inferred by codec type), required if more than one concurrent track per A or V type)
         note: changes to a track: keep track id in new flow, use flow sync to order end/begin

  example: 'http://zenomt.com/ns/rtmfp#media' 00   02 1d 01   05 4c 61 76 63 31   05 01 85 bf 10 01
    (stream ID 1, codec 'avc1', timescale 90000/1, other params default)

message format:

 0 1 2 3 4 5 6 7
+-+-+-+-+-+-+-+-+
|R|O| T |       |
|A|P| S |msgType|
|I|T| S |       |
+-+-+-+-+-+-+-+-+
+~~~~~~~~~~~~~/~+~~~~~~~~~~~~~/~+
|     dts     \ |  pts offset \ |
+~~~~~~~~~~~~~/~+~~~~~~~~~~~~~/~+
+~~~/~~~/~~~~~~~+               +~~~/~~~/~~~~~~~+-------------/-+
| L \ T \   V   |... options ...| L \ T \   V   |       0     \ |
\~~~/~~~/~~~~~~~+   [if(OPT)]   +~~~/~~~/~~~~~~~+-------------/-/
+---------------------------------------------------------------+
|                            payload                            |
+---------------------------------------------------------------/

struct mediaMessage_t
{
    bool_t  randomAccessIndicator :1; // RAI
    bool_t  optionsPresent        :1; // OPT
    uintn_t timestampSelect       :2; // TSS
    uintn_t messageType           :4; // msgType

    if(timestampSelect > 0)
    {
        vlu_t dts :variable*8;
        if(timestampSelect > 1)
            vlu_t offset :variable*8;
        else
            offset = 0;
        if(3 == timestampSelect)
            pts = dts - offset;
        else
            pts = dts + offset;
    }
    else
        dts = pts = 0;

    // Note: pts and dts are timescale ticks since the time origin.

    if(optionsPresent)
        optionList_t options :variable*8;

    uint8_t payload[remainder()];
} :flowMessageLength*8;

  timestamp-select:
    0 dts = pts = 0
    1 <vlu dts> (pts = dts)
    2 <vlu dts> <vlu offset> (pts = dts + offset)
    3 <vlu dts> <vlu offset> (pts = dts - offset)

  message-type:
    0 reserved/forbidden
    1 coded media in payload
    5 media random access checkpoint (ex. "i just sent an IDR") (no payload, timestamp(s) required, dts/pts same as random access media unit)
    6 media alignment checkpoint (ex. "i just sent a non-IDR", possibly useful for long GOPs, timestamp(s) required)
    7 silence/temporary EOS (no payload, timestamp required)
  (8-f non-discardable/must-not-abandon)
    8 reserved/forbidden
    9 sticky codec-specific sequence header/config in payload (ex. AVCC, AudioSpecificConfig)
    f flow sync (payload <vlu syncid> <vlu count>)

  options:
    TBD (example: like RTP extension headers, see RFC 8285, https://www.iana.org/assignments/rtp-parameters/rtp-parameters.xhtml#rtp-parameters-10 )

*/

} } } // namespace com::zenomt::rtmfp
