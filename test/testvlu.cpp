#include <cstdio>
#include <stdexcept>

#include "rtmfp/VLU.hpp"

using namespace com::zenomt::rtmfp;

void print_hex(const uint8_t *buf, size_t len, bool nl = true)
{
	for(size_t x = 0; x < len; x++)
		printf("%.02x ", buf[x]);
	if(nl)
		printf("\n");
}

void print_vlu(uintmax_t v)
{
	uint8_t buf[VLU::MAX_VLU_SIZE];
	size_t len;
	
	printf("%20lu : ", v);
	len = VLU::encode(v, buf);
	print_hex(buf, len);
}

size_t tryParse(const uint8_t *buf, size_t len)
{
	printf("trying to parse %lu: ", len);
	print_hex(buf, len);
	size_t rv = 0;

	const uint8_t *payload = nullptr;
	size_t payloadLen = 0;
	uintmax_t optionType = 0;

	if(0 == (rv = Option::parse(buf, buf + len, &optionType, &payload, &payloadLen)))
		goto error;
	printf("option len: %lu ", rv);
	if(payload)
	{
		printf("type %lu payload (%lu): ", optionType, payloadLen);
		print_hex(payload, payloadLen);
	}
	else
		printf("empty\n");
	
	return rv;

error:
	printf("option parse error\n");
	return 0;
}

int main(int argc, char *argv[])
{
	print_vlu(0);
	print_vlu(16383);
	print_vlu((uintmax_t)9223372036854775808UL);
	print_vlu(UINTMAX_MAX);
	print_vlu(UINTMAX_MAX - 1);

	uint8_t buf[11] = { 0xff, 0x80, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f };
	uintmax_t val = 0;
	size_t len;

	len = VLU::parse(buf, buf + sizeof(buf), &val);
	printf("parsed %lu ", len); print_hex(buf, sizeof(buf), false); printf(" to %lu\n", val);

	len = VLU::parse(buf, buf + sizeof(buf), &val, false);
	printf("parsed %lu ", len); print_hex(buf, sizeof(buf), false); printf(" to %lu (no saturation)\n", val);

	buf[10] = 0xff;
	len = VLU::parse(buf, buf + sizeof(buf), &val);
	printf("parsed %lu ", len); print_hex(buf, sizeof(buf), false); printf(" to %lu\n", val);

	uint8_t buf2[] = { 0x80, 0x80, 0x81, 0x00 };
	len = VLU::parse(buf2, buf2 + sizeof(buf2), &val);
	printf("parsed %lu ", len); print_hex(buf2, sizeof(buf2), false); printf(" to %lu\n", val);


	const uint8_t *payload = buf;
	size_t payloadLen = 0;
	uintmax_t optionType = 3;
	uint8_t option1[] = { 0x80, 0x00, 0xff, 0x01 };
	len = Option::parse(option1, option1 + sizeof(option1), &optionType, &payload, &payloadLen);
	printf("parse option (%lu) ", len); print_hex(option1, len, false); printf("payload: %p len %lu type %lu\n", (void *)payload, payloadLen, optionType);
	tryParse(option1, sizeof(option1));
	printf("\n");

	option1[1] = 0x01;
	len = Option::parse(option1, option1 + sizeof(option1), &optionType, &payload, &payloadLen);
	printf("parse option (%lu) ", len); print_hex(option1, len, false); printf("payload: %p len %lu type %lu\n", (void *)payload, payloadLen, optionType);
	tryParse(option1, sizeof(option1));
	printf("\n");

	option1[2] = 0x7f;
	len = Option::parse(option1, option1 + sizeof(option1), &optionType, &payload, &payloadLen);
	printf("parse option (%lu) ", len); print_hex(option1, len, false); printf("payload: %p len %lu type %lu\n", (void *)payload, payloadLen, optionType);
	tryParse(option1, sizeof(option1));
	printf("\n");

	option1[1] = 0x02;
	len = Option::parse(option1, option1 + sizeof(option1), &optionType, &payload, &payloadLen);
	printf("parse option (%lu) ", len); print_hex(option1, len, false); printf("payload: %p len %lu type %lu\n", (void *)payload, payloadLen, optionType);
	tryParse(option1, sizeof(option1));
	printf("\n");

	option1[1] = 0x03;
	len = Option::parse(option1, option1 + sizeof(option1), &optionType, &payload, &payloadLen);
	printf("parse option (%lu) ", len); print_hex(option1, len, false); printf("payload: %p len %lu type %lu\n", (void *)payload, payloadLen, optionType);
	tryParse(option1, sizeof(option1));
	printf("\n");

	option1[1] = 0x02;
	option1[2] = 0xff;
	option1[3] = 0x7f;
	len = Option::parse(option1, option1 + sizeof(option1), &optionType, &payload, &payloadLen);
	printf("parse option (%lu) ", len); print_hex(option1, len, false); printf("payload: %p len %lu type %lu\n", (void *)payload, payloadLen, optionType);
	tryParse(option1, sizeof(option1));
	printf("\n");

	option1[3] = 0xff;
	len = Option::parse(option1, option1 + sizeof(option1), &optionType, &payload, &payloadLen);
	printf("parse option (%lu) ", len); print_hex(option1, len, false); printf("payload: %p len %lu type %lu\n", (void *)payload, payloadLen, optionType);
	tryParse(option1, sizeof(option1));
	printf("\n");

	option1[0] = 0x00;
	len = Option::parse(option1, option1 + sizeof(option1), &optionType, &payload, &payloadLen);
	printf("parse option (%lu) ", len); print_hex(option1, len, false); printf("payload: %p len %lu type %lu\n", (void *)payload, payloadLen, optionType);
	tryParse(option1, sizeof(option1));
	printf("\n");

	std::vector<uint8_t> option2;
	Option::append(3, "hi there", 8, option2);
	tryParse(option2.data(), option2.size());
	printf("\n");

	option2.clear();
	Option::append(4, 8, option2);
	tryParse(option2.data(), option2.size());
	printf("\n");

	option2.clear();
	Option::append(5, option2);
	tryParse(option2.data(), option2.size());
	printf("\n");

	option2.clear();
	Option::append(option2);
	tryParse(option2.data(), option2.size());
	printf("\n");

	return 0;
}
