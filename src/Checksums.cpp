// Copyright © 2021 Michael Thornburgh
// SPDX-License-Identifier: MIT

#include "../include/rtmfp/Checksums.hpp"

namespace com { namespace zenomt {

uint32_t crc32_le(uint32_t crc, const void *buf_, size_t len)
{
	const uint8_t *buf = (const uint8_t *)buf_;

	for(size_t i = 0; i < len; i++)
	{
		uint8_t c = buf[i];
		for(int j = 0; j < 8; j++)
		{
			uint32_t bit = (c ^ crc) & 0x01;
			crc >>= 1;
			if(bit)
				crc = crc ^ 0xEDB88320;
			c >>= 1;
		}
	}

	return crc;
}

uint32_t crc32_le(const void *buf, size_t len)
{
	return crc32_le(~0L, buf, len);
}

uint32_t crc32_be(uint32_t crc, const void *buf_, size_t len)
{
	const uint8_t *buf = (const uint8_t *)buf_;

	for(size_t i = 0; i < len; i++)
	{
		uint8_t c = buf[i];
		for(int j = 0; j < 8; j++)
		{
			uint32_t bit = (c ^ (crc >> 24)) & 0x80;
			crc <<= 1;
			if(bit)
				crc = crc ^ 0x04C11DB7;
			c <<= 1;
		}
	}

	return crc;
}

uint32_t crc32_be(const void *buf, size_t len)
{
	return crc32_be(~0L, buf, len);
}

// in_cksum() is derived from the public domain ping.c by Mike Muuss, US Army
// Ballistic Research Laboratory, December 1983.

uint16_t in_cksum(const void *buf, size_t len)
{
	size_t nleft = len;
	const uint8_t *w = (const uint8_t *)buf;
	uint32_t sum = 0;
	uint16_t answer = 0;

	/*
	 * Our algorithm is simple, using a 32 bit accumulator (sum), we add
	 * sequential 16 bit words to it, and at the end, fold back all the
	 * carry bits from the top 16 bits into the lower 16 bits.
	 */
	while (nleft > 1)  {
		sum += *(w++) << 8;
		sum += *(w++)     ;
		nleft -= 2;
	}

	/* mop up an odd byte, if necessary */
	if (nleft == 1) {
		sum += *w;
	}

	/* add back carry outs from top 16 bits to low 16 bits */
	// note original used "int" for sum, and the shift-right would have
	// sign-extended if there were enough carries. our sum is unsigned
	// so there's no sign extension. for all practical uses of the Internet
	// checksum, there could never be that many carries, so there shouldn't
	// be any compatibility issue.
	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add carry */
	answer = ~sum;				/* truncate to 16 bits */

	return(answer);
}

} } // namespace com::zenomt
