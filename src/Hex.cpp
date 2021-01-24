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

} } // namespace com::zenomt
