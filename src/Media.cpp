// Copyright © 2021 Michael Thornburgh
// SPDX-License-Identifier: MIT

#include "../include/rtmfp/Media.hpp"
#include "../include/rtmfp/VLU.hpp"

#include <cstring>

namespace com { namespace zenomt { namespace rtmfp {

namespace {

const uint8_t _signature[] = "http://zenomt.com/ns/rtmfp#media";
constexpr long double _scale64 = 4294967296.0L * 4294967296.0L; // 18446744073709551616.0L, but just to be safe

uint64_t _readU64(const uint8_t *val)
{
	uint64_t rv = 0;
	for(int i = 0; i < 8; i++)
	{
		rv <<= 8;
		rv += val[i];
	}
	return rv;
}

void _writeU64(uint8_t *dst, uint64_t val)
{
	for(int i = 64 - 8; i >= 0; i -= 8)
		*dst++ = (val >> i) & 0xff;
}

Time _fromNTP4(const uint8_t *val)
{
	if(*val >= 0x80)
		return -1.0;

	Time rv = Time(_readU64(val));

	Time fraction = Time(_readU64(val + 8));
	fraction /= _scale64;

	return rv + fraction;
}

void _toNTP4(uint8_t *dst, Time val)
{
	Time intpart;
	Time fraction = std::modf(val, &intpart);
	_writeU64(dst, uint64_t(intpart));
	_writeU64(dst + 8, uint64_t(fraction * _scale64));
}

} // anonymous namespace in com::zenomt::rtmfp

Media::Media(const Media &other) :
	streamID(other.streamID),
	trackID(other.trackID),
	codec(other.codec),
	mediaType(other.mediaType),
	trackName(other.trackName),
	reorderSuggestion(other.reorderSuggestion),
	m_origin(other.m_origin),
	m_timescale_ticks(other.m_timescale_ticks),
	m_timescale_perSeconds(other.m_timescale_perSeconds),
	m_receiveIntent(other.m_receiveIntent)
{
}

std::shared_ptr<Media> Media::fromMetadata(const Bytes &metadata)
{
	auto rv = share_ref(new Media(), false);
	if(0 == rv->setFromMetadata(metadata))
		return nullptr;
	return rv;
}

size_t Media::setFromMetadata(const Bytes &metadata)
{
	const uint8_t *bytes = metadata.data();
	const uint8_t *cursor = bytes;
	const uint8_t *limit = cursor + metadata.size();

	if((metadata.size() < sizeof(_signature)) or memcmp(cursor, _signature, sizeof(_signature)))
		return 0;
	cursor += sizeof(_signature);

	uintmax_t reorderSuggestionTicks = 0;
	bool sawReorderSuggestion = false;
	bool sawStreamID = false;
	bool sawCodec = false;

	while(cursor < limit)
	{
		size_t rv;
		uintmax_t type_ = 0;
		const uint8_t *value = nullptr;
		size_t valueLen = 0;

		if(0 == (rv = Option::parse(cursor, limit, &type_, &value, &valueLen)))
			return 0;
		cursor += rv;
		if(not value)
			continue; // skip markers

		const uint8_t *optionLimit = value + valueLen;

		switch(type_)
		{
		case OPTION_STREAM_ID:
			if(0 == VLU::parse(value, optionLimit, &streamID))
				return 0;
			sawStreamID = true;
			break;

		case OPTION_CODEC:
			codec = std::string((const char *)value, valueLen);
			sawCodec = true;
			break;

		case OPTION_MEDIA_TYPE:
			mediaType = std::string((const char *)value, valueLen);
			break;

		case OPTION_TIME_ORIGIN:
			if(valueLen < 16)
				return 0;
			if(not setOrigin(_fromNTP4(value)))
				return 0;
			break;

		case OPTION_TIMESCALE:
			{
				uintmax_t tmpTicks = 0;
				uintmax_t tmpPerSeconds = 0;
				if(0 == (rv = VLU::parse(value, optionLimit, &tmpTicks)))
					return 0;
				value += rv;
				if(0 == VLU::parse(value, optionLimit, &tmpPerSeconds))
					return 0;
				if(not setTimescale(tmpTicks, tmpPerSeconds))
					return 0;
			}
			break;

		case OPTION_RECEIVE_INTENT_NETWORK:
			setReceiveIntent(RO_NETWORK);
			break;

		case OPTION_REORDER_SUGGESTION:
			if(0 == VLU::parse(value, value + valueLen, &reorderSuggestionTicks))
				return 0;
			sawReorderSuggestion = true;
			break;

		case OPTION_TRACK_NAME:
			trackName = std::string((const char *)value, valueLen);
			break;

		case OPTION_TRACK_ID:
			if(0 == VLU::parse(value, value + valueLen, &trackID))
				return 0;
			break;

		default:
			break;
		}
	}

	if(not (sawStreamID and sawCodec))
		return 0;

	if(sawReorderSuggestion)
		reorderSuggestion = reorderSuggestionTicks * getTickDuration();

	return cursor - bytes;
}

Bytes Media::toMetadata() const
{
	Bytes rv(_signature, _signature + sizeof(_signature));

	Option::append(OPTION_STREAM_ID, streamID, rv);
	Option::append(OPTION_CODEC, codec.data(), codec.size(), rv);

	if(mediaType.size())
		Option::append(OPTION_MEDIA_TYPE, mediaType.data(), mediaType.size(), rv);

	if(m_origin > 0)
	{
		uint8_t tmp[16];
		_toNTP4(tmp, m_origin);
		Option::append(OPTION_TIME_ORIGIN, tmp, sizeof(tmp), rv);
	}

	if((DEFAULT_TIMESCALE_TICKS != m_timescale_ticks) or (DEFAULT_TIMESCALE_PER_SECONDS != m_timescale_perSeconds))
	{
		Bytes tmp;
		VLU::append(m_timescale_ticks, tmp);
		VLU::append(m_timescale_perSeconds, tmp);
		Option::append(OPTION_TIMESCALE, tmp, rv);
	}

	if(RO_NETWORK == m_receiveIntent)
		Option::append(OPTION_RECEIVE_INTENT_NETWORK, rv);

	if((reorderSuggestion >= 0) and std::isfinite(reorderSuggestion))
		Option::append(OPTION_REORDER_SUGGESTION, (uintmax_t)((reorderSuggestion + getTickDuration() / Time(2.0)) / getTickDuration()), rv);

	if(trackName.size())
		Option::append(OPTION_TRACK_NAME, trackName.data(), trackName.size(), rv);

	if(trackID)
		Option::append(OPTION_TRACK_ID, trackID, rv);

	return rv;
}

void Media::setTrackID(uintmax_t trackID_)
{
	trackID = trackID_;
}

uintmax_t Media::getTrackID() const
{
	return trackID;
}

void Media::clearTrackID()
{
	trackID = 0;
}

bool Media::hasTrackID() const
{
	return true;
}

bool Media::setOrigin(Time origin)
{
	if((origin < 0) or not std::isfinite(origin))
		return false;
	m_origin = origin;
	return true;
}

Time Media::getOrigin() const
{
	return m_origin;
}

bool Media::setTimescale(uintmax_t ticks, uintmax_t perSeconds)
{
	if((not ticks) or (not perSeconds))
		return false;
	m_timescale_ticks = ticks;
	m_timescale_perSeconds = perSeconds;
	return true;
}

void Media::getTimescale(uintmax_t *ticks, uintmax_t *perSeconds) const
{
	if(ticks)
		*ticks = m_timescale_ticks;
	if(perSeconds)
		*perSeconds = m_timescale_perSeconds;
}

Time Media::getTickDuration() const
{
	return Time(m_timescale_perSeconds) / Time(m_timescale_ticks);
}

bool Media::setReceiveIntent(ReceiveOrder intent)
{
	if(RO_HOLD == intent)
		return false;
	m_receiveIntent = intent;
	return true;
}

ReceiveOrder Media::getReceiveIntent() const
{
	return m_receiveIntent;
}

Bytes Media::basicMakeMessage(bool rai, int messageType, uintmax_t dtsTicks, uintmax_t ptsTicks, const void *optionList_, size_t optionListLen, const void *payload_, size_t len)
{
	const uint8_t *optionList = (const uint8_t *)optionList_;
	const uint8_t *payload = (const uint8_t *)payload_;

	uintmax_t offset = 0;

	uint8_t tss = TSS_NONE;
	if(dtsTicks or ptsTicks)
	{
		if(ptsTicks == dtsTicks)
			tss = TSS_DTS;
		else if(ptsTicks < dtsTicks)
		{
			tss = TSS_DTS_MINUS_OFFSET;
			offset = dtsTicks - ptsTicks;
		}
		else
		{
			tss = TSS_DTS_PLUS_OFFSET;
			offset = ptsTicks - dtsTicks;
		}
	}

	Bytes rv;

	rv.push_back((rai ? FLAG_RAI : 0) | (optionListLen ? FLAG_OPT : 0) | tss | (messageType & MSG_MASK));

	if(tss > TSS_NONE)
	{
		VLU::append(dtsTicks, rv);
		if(tss > TSS_DTS)
			VLU::append(offset, rv);
	}

	if(optionListLen)
		rv.insert(rv.end(), optionList, optionList + optionListLen);

	if(len)
		rv.insert(rv.end(), payload, payload + len);

	return rv;
}

Bytes Media::makeMessage(bool rai, int messageType, Time dts, Time pts, const void *optionList_, size_t optionListLen, const void *payload_, size_t len) const
{
	if(pts < 0)
		pts = dts;

	return basicMakeMessage(rai, messageType, timeToTicks(dts), timeToTicks(pts), optionList_, optionListLen, payload_, len);
}

Bytes Media::makeMessage(bool rai, int messageType, Time dts, Time pts, const void *payload, size_t len) const
{
	return makeMessage(rai, messageType, dts, pts, nullptr, 0, payload, len);
}

Bytes Media::makeMessage(bool rai, int messageType, Time dts, Time pts, const Bytes &optionList, const Bytes &payload) const
{
	return makeMessage(rai, messageType, dts, pts, optionList.data(), optionList.size(), payload.data(), payload.size());
}

Bytes Media::makeMessage(bool rai, int messageType, Time dts, Time pts, const Bytes &payload) const
{
	return makeMessage(rai, messageType, dts, pts, nullptr, 0, payload.data(), payload.size());
}

size_t Media::basicParseHeader(const uint8_t *message, size_t len, bool *outRAI, int *outMessageType, uintmax_t *outDTSTicks, uintmax_t *outPTSTicks, size_t *outOptionListOffset)
{
	const uint8_t *limit = message + len;
	size_t rv;

	if(len < 1)
		return 0;

	const uint8_t *cursor = message + 1; // after the flags

	if(outRAI)
		*outRAI = *message & FLAG_RAI;
	if(outMessageType)
		*outMessageType = *message & MSG_MASK;

	uintmax_t dtsTicks = 0;
	uintmax_t offsetTicks = 0;

	uint8_t tss = *message & TSS_MASK;
	if(tss > TSS_NONE)
	{
		if(0 == (rv = VLU::parse(cursor, limit, &dtsTicks)))
			return 0;
		cursor += rv;
		if(tss > TSS_DTS)
		{
			if(0 == (rv = VLU::parse(cursor, limit, &offsetTicks)))
				return 0;
			cursor += rv;
		}
	}

	uintmax_t ptsTicks;
	if(TSS_DTS_MINUS_OFFSET == tss)
	{
		if(offsetTicks > dtsTicks)
			return 0;
		ptsTicks = dtsTicks - offsetTicks;
	}
	else
		ptsTicks = dtsTicks + offsetTicks;

	if(outDTSTicks)
		*outDTSTicks = dtsTicks;
	if(outPTSTicks)
		*outPTSTicks = ptsTicks;

	if(outOptionListOffset)
		*outOptionListOffset = cursor - message;

	if(*message & FLAG_OPT)
	{
		const uint8_t *value = nullptr;
		while(true)
		{
			if(0 == (rv = Option::parse(cursor, limit, nullptr, &value, nullptr)))
				return 0;
			cursor += rv;
			if(not value)
				break;
		}
		if(value)
			return 0; // option list MUST be terminated or it's malformed
	}

	return cursor - message;
}

size_t Media::parseHeader(const uint8_t *message, size_t len, bool *outRAI, int *outMessageType, Time *outDTS, Time *outPTS, size_t *outOptionListOffset) const
{
	uintmax_t dtsTicks;
	uintmax_t ptsTicks;

	size_t rv = basicParseHeader(message, len, outRAI, outMessageType, &dtsTicks, &ptsTicks, outOptionListOffset);
	if(rv)
	{
		if(outDTS)
			*outDTS = ticksToTime(dtsTicks);
		if(outPTS)
			*outPTS = ticksToTime(ptsTicks);
	}

	return rv;
}

Time Media::ticksToTime(uintmax_t ticks) const
{
	return m_origin + ticks * getTickDuration();
}

uintmax_t Media::timeToTicks(Time t) const
{
	if((t < m_origin) or not std::isfinite(t))
		t = m_origin;

	Time rounding = getTickDuration() / Time(2.0);
	return uintmax_t((t + rounding - m_origin) / getTickDuration());
}

bool Media::encodingParametersEqual(const Media &other) const
{
	return (m_timescale_ticks == other.m_timescale_ticks)
	   and (m_timescale_perSeconds == other.m_timescale_perSeconds)
	   and (m_receiveIntent == other.m_receiveIntent)
	   and (codec == other.codec)
	   and (mediaType == other.mediaType)

	   // this is a tricky case since there's rounding going to/from metadata
	   and (((reorderSuggestion < 0) and (other.reorderSuggestion < 0)) or (std::fabs(reorderSuggestion - other.reorderSuggestion) < 2.0 * getTickDuration()))

	   // this is also tricky but probably close enough
	   and (std::fabs(m_origin - other.m_origin) < getTickDuration() / 2.0)
	;
}

bool Media::encodingAndTrackParametersEqual(const Media &other) const
{
	return (encodingParametersEqual(other))
	   and (trackID == other.trackID)
	   and (trackName == other.trackName)
	;
}

bool Media::parametersEqual(const Media &other) const
{
	return encodingAndTrackParametersEqual(other) and (streamID == other.streamID);
}

bool Media::operator== (const Media &rhs) const
{
	return parametersEqual(rhs);
}

bool Media::operator!= (const Media &rhs) const
{
	return not parametersEqual(rhs);
}

} } } // namespace com::zenomt::rtmfp
