// Copyright © 2021 Michael Thornburgh
// SPDX-License-Identifier: MIT

#include <cstdio>
#include <cstdint>
#include <cctype>

#include "../include/rtmfp/Hex.hpp"

namespace com { namespace zenomt {

void Hex::print(const char *msg, const void *bytes, const void *limit)
{
	if(limit < bytes)
		return;
	return print(msg, bytes, ((uint8_t *)limit) - ((uint8_t *)bytes));
}

void Hex::print(const char *msg, const void *bytes_, size_t len)
{
	const uint8_t *bytes = (const uint8_t *)bytes_;

	printf("%s (%ld)\n", msg, (unsigned long)len);
	size_t x = 0;
	while(x < len)
	{
		char buf[17] = { 0 };
		size_t c = 0;

		printf("%08lx  ", (unsigned long)x);
		for(size_t y = 0; y < 16; y++)
		{
			if(x + y < len)
			{
				uint8_t b = bytes[x + y];
				printf("%02x ", b);
				buf[y] = isprint(b) ? (char)b : '.';
				c++;
			}
			else
				printf("   ");
		}

		printf(" |%s|\n", buf);
		x += c;
	}
	printf("%08lx\n", (unsigned long)x);
}

void Hex::dump(const char *msg, const void *bytes_, const void *limit_, bool nl)
{
	const uint8_t *bytes = (uint8_t *)bytes_;
	const uint8_t *limit = (uint8_t *)limit_;

	printf("%s (%lu): ", msg, limit - bytes);
	while(bytes < limit)
		printf("%02x ", *bytes++);
	if(nl)
		printf("\n");
}

void Hex::dump(const char *msg, const void *bytes, size_t len, bool nl)
{
	dump(msg, bytes, (const uint8_t *)bytes + len, nl);
}

std::string Hex::encode(const void *bytes, size_t len)
{
	return encode(bytes, ((const uint8_t *)bytes) + len);
}

static char _digits[] = "0123456789abcdef";

std::string Hex::encode(const void *bytes_, const void *limit_)
{
	const uint8_t *bytes = (const uint8_t *)bytes_;
	const uint8_t *limit = (const uint8_t *)limit_;
	std::string rv;

	while(bytes < limit)
	{
		uint8_t b = *bytes;
		rv.push_back(_digits[b >> 4]);
		rv.push_back(_digits[b & 0x0f]);
		bytes++;
	}

	return rv;
}

static int _xdigitToInt(char d)
{
	if((d >= '0') and (d <= '9'))
		return d - '0';
	if((d >= 'a') and (d <= 'f'))
		return d - 'a' + 0x0a;
	if((d >= 'A') and (d <= 'F'))
		return d - 'A' + 0x0a;
	if(isspace(d))
		return -1;
	return -2;
}

bool Hex::decode(const char *hex, std::vector<uint8_t> &dst)
{
	const char *cursor = hex;
	char d;
	uint8_t val = 0;
	bool onFirstDigit = true;
	size_t originalSize = dst.size();

	while((d = *cursor++))
	{
		int digit = _xdigitToInt(d);
		if(digit < 0)
		{
			if((digit < -1) or not onFirstDigit)
				goto fail;
			continue;
		}

		val <<= 4;
		val += digit;

		if(not onFirstDigit)
		{
			dst.push_back(val);
			val = 0;
		}

		onFirstDigit = not onFirstDigit;
	}

	if(onFirstDigit)
		return true;

fail:
	dst.resize(originalSize);
	return false;
}

} } // namespace com::zenomt
