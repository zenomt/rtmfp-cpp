#include <cassert>
#include <cstdio>
#include <cstring>

#include "rtmfp/Checksums.hpp"

using namespace com::zenomt;

int main(int argc, char *argv[])
{
	char str[] = { 'T', 'h', 'e', ' ', 'q', 'u', 'i', 'c', 'k', ' ', 'b', 'r', 'o', 'w', 'n', ' ', 'f', 'o', 'x', ' ', 'j', 'u', 'm', 'p', 's', ' ', 'o', 'v', 'e', 'r', ' ', 't', 'h', 'e', ' ', 'l', 'a', 'z', 'y', ' ', 'd', 'o', 'g', 0, 0, 0, 0 };

	uint8_t buf[] = { 1, 2, 3, 4, 5 };
	assert(in_cksum(buf, sizeof(buf)) == ((0x0102 + 0x0304 + 0x05) ^ 0xffff)); // no carries

	// assert( ~crc32_le(str, strlen(str)) == 1095738169 ); // from "cksum -o 3"

	uint8_t crc_buf[4] = { 0 };
	uint32_t crc = crc32_le(str, sizeof(str) - 4);
	printf("crc32_le of '%s': %08X / %u  inv: %08X / %u\n", str, crc, crc, ~crc, ~crc);
	crc_buf[3] = str[sizeof(str) - 1] = (crc >> 24) & 0xff;
	crc_buf[2] = str[sizeof(str) - 2] = (crc >> 16) & 0xff;
	crc_buf[1] = str[sizeof(str) - 3] = (crc >>  8) & 0xff;
	crc_buf[0] = str[sizeof(str) - 4] = (crc      ) & 0xff;
	assert(0 == crc32_le(str, sizeof(str)));
	assert(0 == crc32_le(crc32_le(str, sizeof(str) - 4), crc_buf, sizeof(crc_buf))); // scatter-gather incremental crc

	str[sizeof(str) - 4] = 0; // put back null terminator for printf

	crc = crc32_be(str, sizeof(str) - 4);
	printf("crc32_be of '%s': %08X / %u  inv: %08X / %u\n", str, crc, crc, ~crc, ~crc);
	crc_buf[0] = str[sizeof(str) - 4] = (crc >> 24) & 0xff;
	crc_buf[1] = str[sizeof(str) - 3] = (crc >> 16) & 0xff;
	crc_buf[2] = str[sizeof(str) - 2] = (crc >>  8) & 0xff;
	crc_buf[3] = str[sizeof(str) - 1] = (crc      ) & 0xff;
	assert(0 == crc32_be(str, sizeof(str)));
	assert(0 == crc32_be(crc32_be(str, sizeof(str) - 4), crc_buf, sizeof(crc_buf))); // scatter-gather incremental crc

	// values from ffmpeg unit test
	uint8_t ffmpeg_test[1999];
	for(unsigned i = 0; i < sizeof(ffmpeg_test); i++)
		ffmpeg_test[i] = i + i * i;

	assert(0x3d5cdd04 == crc32_le(0, ffmpeg_test, sizeof(ffmpeg_test)));
	assert(0xc0f5bae0 == crc32_be(0, ffmpeg_test, sizeof(ffmpeg_test)));

	str[sizeof(str) - 4] = sizeof(str) - 4;
	crc = ~crc32_be(0, str, sizeof(str) - 3);
	printf("posix cksum %08X %u\n", crc, crc);

	return 0;
}
