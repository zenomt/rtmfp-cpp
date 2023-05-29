#pragma once

// Copyright © 2021 Michael Thornburgh
// SPDX-License-Identifier: MIT

// Helpers for http://zenomt.com/ns/rtmfp#media media flows:
// a flow type, including metadata and message encapsulation
// formats, for general-purpose real-time media streams in RTMFP
// beyond Flash Media. See namespace.ttl for details.

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
	uintmax_t   trackID { 0 };
	std::string codec;
	std::string mediaType; // "audio", "video", "text", "application", "message", "image", ...
	std::string trackName;
	Time        reorderSuggestion { -1.0 }; // < 0 means no suggestion

	/* [[deprecated]] */ void      setTrackID(uintmax_t trackID);
	/* [[deprecated]] */ uintmax_t getTrackID() const;
	/* [[deprecated]] */ void      clearTrackID();
	/* [[deprecated]] */ bool      hasTrackID() const;

	bool setOrigin(Time origin); // origin must be non-negative and finite
	Time getOrigin() const;
	bool setTimescale(uintmax_t ticks, uintmax_t perSeconds);
	void getTimescale(uintmax_t *ticks, uintmax_t *perSeconds) const;
	Time getTickDuration() const;

	bool         setReceiveIntent(ReceiveOrder intent); // intent must be RO_SEQUENCE or RO_NETWORK
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

	bool operator== (const Media &rhs) const;
	bool operator!= (const Media &rhs) const;

	static constexpr uint8_t FLAG_RAI = 0x80;
	static constexpr uint8_t FLAG_OPT = 0x40;

	enum {
		MSG_PADDING                  = 0,
		MSG_MEDIA                    = 1,
		MSG_MEDIA_SEGMENT            = 2,
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
		OPTION_MEDIA_TYPE             = 0x44,
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
};

} } } // namespace com::zenomt::rtmfp
