// Copyright © 2021 Michael Thornburgh
// SPDX-License-Identifier: MIT

#include <cstring>
#include <stdexcept>

#include "../include/rtmfp/VLU.hpp"

namespace com { namespace zenomt { namespace rtmfp {

size_t VLU::encode(uintmax_t val, void *dst)
{
	uint8_t buf[MAX_VLU_SIZE];
	int i = sizeof(buf);
	size_t rv = 0;

	do
	{
		i--;
		buf[i] = (uint8_t)(val & 0x7f) | (rv ? 0x80 : 0);
		rv++;
		val >>= 7;
	} while(val);

	if(dst)
		memmove(dst, buf + i, rv);

	return rv;
}

void VLU::append(uintmax_t val, std::vector<uint8_t> &dst)
{
	uint8_t buf[MAX_VLU_SIZE];
	size_t rv = encode(val, buf);
	dst.insert(dst.end(), buf, buf + rv);
}

size_t VLU::parse(const uint8_t *src, const uint8_t *limit, uintmax_t *val, bool saturate)
{
	uintmax_t value = 0;
	size_t rv = 0;
	bool saturated = false;
	const uintmax_t MAX_BEFORE_SATURATE = UINTMAX_MAX >> 7;

	while((not limit) or (src < limit))
	{
		if(value > MAX_BEFORE_SATURATE)
			saturated = true;

		value = (value << 7) + (*src & 0x7f);
		rv++;
		if(not (*src & 0x80))
			break;
		src++;
	}

	if(limit and (src >= limit))
		return 0;

	if(saturated and saturate)
		value = UINTMAX_MAX;

	if(val)
		*val = value;

	return rv;
}

size_t VLU::parseField(const uint8_t *src, const uint8_t *limit, const uint8_t **outPayload, size_t *payloadLen)
{
	const uint8_t *cursor = src;
	uintmax_t fieldLength = 0;
	size_t rv;

	if(0 == (rv = VLU::parse(cursor, limit, &fieldLength)))
		return 0;
	cursor += rv;

	if(limit and (fieldLength > (uintmax_t)(limit - cursor)))
		return 0;

	if(outPayload)
		*outPayload = cursor;
	if(payloadLen)
		*payloadLen = fieldLength;

	return rv + fieldLength;
}

size_t Option::parse(const uint8_t *src, const uint8_t *limit, uintmax_t *type_, const uint8_t **outValue, size_t *outValueLen)
{
	const uint8_t *fieldPayload = nullptr;
	size_t fieldPayloadLen = 0;
	const uint8_t *optionLimit = nullptr;
	const uint8_t *value = nullptr;
	uintmax_t optionType = 0;
	size_t fieldConsumed;

	if(0 == (fieldConsumed = VLU::parseField(src, limit, &fieldPayload, &fieldPayloadLen)))
		return 0;
	optionLimit = fieldPayload + fieldPayloadLen;

	if(0 == fieldPayloadLen)
		goto finish;

	size_t rv;
	if(0 == (rv = VLU::parse(fieldPayload, optionLimit, &optionType)))
		return 0;
	value = fieldPayload + rv;

finish:
	if(type_)
		*type_ = optionType;
	if(outValueLen)
		*outValueLen = value ? optionLimit - value : 0;
	if(outValue)
		*outValue = value;

	return fieldConsumed;
}

void Option::append(uintmax_t type_, const void *value_, size_t valueLen, std::vector<uint8_t> &dst)
{
	const uint8_t *value = (const uint8_t *)value_;
	uint8_t typeVLU[VLU::MAX_VLU_SIZE];
	uint8_t lenVLU[VLU::MAX_VLU_SIZE];

	size_t typeLen = VLU::encode(type_, typeVLU);
	size_t lenLen = VLU::encode(typeLen + valueLen, lenVLU);

	dst.insert(dst.end(), lenVLU, lenVLU + lenLen);
	dst.insert(dst.end(), typeVLU, typeVLU + typeLen);
	dst.insert(dst.end(), value, value + valueLen);
}

void Option::append(uintmax_t type_, uintmax_t value, std::vector<uint8_t> &dst)
{
	uint8_t valueVLU[VLU::MAX_VLU_SIZE];
	size_t valueLen = VLU::encode(value, valueVLU);
	append(type_, valueVLU, valueLen, dst);
}

void Option::append(uintmax_t type_, std::vector<uint8_t> &dst)
{
	append(type_, nullptr, 0, dst);
}

void Option::append(std::vector<uint8_t> &dst)
{
	VLU::append(0, dst);
}

} } } // namespace com::zenomt::rtmfp
