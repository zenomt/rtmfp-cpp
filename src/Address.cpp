// Copyright © 2021 Michael Thornburgh
// SPDX-License-Identifier: MIT

#include "../include/rtmfp/Address.hpp"

#include <arpa/inet.h>
#include <cstdio>
#include <cstring>

namespace com { namespace zenomt { namespace rtmfp {

Address::Address() : m_origin(ORIGIN_UNKNOWN)
{
	erase();
}

Address::Address(const Address &other) : m_addr(other.m_addr), m_origin(other.m_origin) { }

Address::Address(const struct sockaddr *addr, Origin origin) : m_origin(origin)
{
	setSockaddr(addr);
}

void Address::erase()
{
	memset(&m_addr, 0, sizeof(m_addr));
}

bool Address::setFamily(int family)
{
	if((AF_INET != family) && (AF_INET6 != family))
		return false;

	if(getFamily() == family)
		return true;

	unsigned savedPort = getPort();
	uint8_t savedAddress[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0 };
	size_t savedAddressLength = canMapToFamily(family) ? getIPAddress(savedAddress + (AF_INET6 == family ? 12 : 0)) : 0;

	erase();

	m_addr.s.sa_family = family;
#ifdef SIN6_LEN
	m_addr.s.sa_len = getSockaddrLen();
#endif
	setPort(savedPort);

	if(savedAddressLength)
	{
		if(AF_INET == family) // converting from mapped AF_INET6 to AF_INET
			memmove(&m_addr.s4.sin_addr, savedAddress + 12, 4);
		else // converting from AF_INET to AF_INET6
			memmove(&m_addr.s6.sin6_addr, savedAddress, 16);
	}

	return true;
}

bool Address::canMapToFamily(int family) const
{
	static const uint8_t map_prefix[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };

	if(getFamily() == family)
		return true;

	switch(getFamily())
	{
	case AF_INET:
		if(AF_INET6 == family)
			return true; // can always map AF_INET to AF_INET6
		break;

	case AF_INET6:
		if((AF_INET == family) && (0 == memcmp(&m_addr.s6.sin6_addr, map_prefix, sizeof(map_prefix))))
			return true; // an IPv4 address mapped to IPv6, so can be un-mapped
		break;
	}

	return false;
}

void Address::setPort(unsigned port)
{
	switch(getFamily())
	{
	case AF_INET:
		m_addr.s4.sin_port = htons(port);
		break;

	case AF_INET6:
		m_addr.s6.sin6_port = htons(port);
		break;
	}
}

unsigned Address::getPort() const
{
	switch(getFamily())
	{
	case AF_INET: return ntohs(m_addr.s4.sin_port);
	case AF_INET6: return ntohs(m_addr.s6.sin6_port);
	default: return 0;
	}
}

size_t Address::getIPAddressLength() const
{
	switch(getFamily())
	{
	case AF_INET: return 4;
	case AF_INET6: return 16;
	}

	return 0;
}

const uint8_t * Address::getIPAddressPtr() const
{
	switch(getFamily())
	{
	case AF_INET: return (uint8_t *)&m_addr.s4.sin_addr;
	case AF_INET6: return (uint8_t *)&m_addr.s6.sin6_addr;
	}

	return nullptr;
}

size_t Address::getIPAddress(uint8_t *dst) const
{
	size_t addrLen = getIPAddressLength();
	memmove(dst, getIPAddressPtr(), addrLen);
	return addrLen;
}

std::vector<uint8_t> Address::getIPAddress() const
{
	uint8_t buf[16] = { 0 };
	size_t len = getIPAddress(buf);
	return std::vector<uint8_t>(buf, buf + len);
}

bool Address::setIPAddress(const uint8_t *src, size_t len)
{
	switch(len)
	{
	case 4:
		setFamily(AF_INET);
		memmove(&m_addr.s4.sin_addr, src, 4);
		return true;

	case 16:
		setFamily(AF_INET6);
		memmove(&m_addr.s6.sin6_addr, src, 16);
		return true;
	}

	return false;
}

size_t Address::setFromEncoding(const uint8_t *src, const uint8_t *limit)
{
	if(limit < src)
		return 0;

	size_t available = limit - src;
	if(available < 1)
		return 0;

	bool is6 = *src & 0x80;
	int origin = *src & 0x03;
	size_t addressLength = is6 ? 16 : 4;
	size_t encodedLength = 1 + addressLength + 2;
	if(available < encodedLength)
		return 0;

	src++;
	setIPAddress(src, addressLength);
	src += addressLength;

	setPort((src[0] << 8) + src[1]);

	m_origin = (Origin)origin;

	return encodedLength;
}

size_t Address::getEncodedLength() const
{
	switch(getFamily())
	{
	case AF_INET: return 1 + 4 + 2;
	case AF_INET6: return 1 + 16 + 2;
	}

	return 0;
}

size_t Address::encode(uint8_t *dst_) const
{
	uint8_t *dst = dst_;

	size_t addressLength = getIPAddressLength();
	if(0 == addressLength)
		return 0;

	*dst = (AF_INET6 == getFamily() ? 0x80 : 0) | m_origin;
	dst++;

	dst += getIPAddress(dst);

	unsigned port = getPort();
	*(dst++) = port >> 8;
	*(dst++) = port & 0xff;

	return dst - dst_;
}

std::vector<uint8_t> Address::encode() const
{
	uint8_t buf[MAX_ENCODED_SIZE] = { 0 };
	size_t size = encode(buf);
	return std::vector<uint8_t>(buf, buf + size);
}

bool Address::setSockaddr(const struct sockaddr *addr)
{
	switch(addr->sa_family)
	{
	case AF_INET:
	case AF_INET6:
		memmove(&m_addr.s, addr, getSockaddrLen(addr));
		return true;
	}

	return false;
}

size_t Address::getSockaddrLen() const
{
	return getSockaddrLen(&m_addr.s);
}

size_t Address::getSockaddrLen(const struct sockaddr *addr)
{
	switch(addr->sa_family)
	{
	case AF_INET: return sizeof(struct sockaddr_in);
	case AF_INET6: return sizeof(struct sockaddr_in6);
	}

	return 0;
}

Address& Address::operator= (const Address &rhs)
{
	m_addr = rhs.m_addr;
	m_origin = rhs.m_origin;

	return *this;
}

bool Address::operator< (const Address &rhs) const
{
	int family = getFamily();
	int rhsFamily = rhs.getFamily();

	if(family < rhsFamily)
		return true;
	if(rhsFamily < family)
		return false;

	// same family, so addrs are the same size

	int cmp = memcmp(getIPAddressPtr(), rhs.getIPAddressPtr(), getIPAddressLength());
	if(cmp < 0)
		return true;
	if(cmp > 0)
		return false;

	return getPort() < rhs.getPort();
}

bool Address::operator== (const Address &rhs) const
{
	return ( (getFamily() == rhs.getFamily())
	      && (0 == memcmp(getIPAddressPtr(), rhs.getIPAddressPtr(), getIPAddressLength()))
	      && (getPort() == rhs.getPort())
	);
}

std::string Address::toPresentation(bool withPort) const
{
	char presentation[MAX_PRESENTATION_LENGTH] = { 0 };
	toPresentation(presentation, withPort);
	return std::string(presentation);
}

void Address::toPresentation(char *dst, bool withPort) const
{
	char buf[INET6_ADDRSTRLEN]; // big enough for INET too

	*dst = 0; // just in case

	if(not inet_ntop(getFamily(), getIPAddressPtr(), buf, sizeof(buf)))
		return;

	if(not withPort)
		snprintf(dst, MAX_PRESENTATION_LENGTH, "%s", buf);
	else
	{
		if(AF_INET == getFamily())
			snprintf(dst, MAX_PRESENTATION_LENGTH, "%s:%d", buf, getPort());
		else
			snprintf(dst, MAX_PRESENTATION_LENGTH, "[%s]:%d", buf, getPort());
	}
}

static size_t _count_colons(const char *src)
{
	size_t rv = 0;
	char ch;
	while((ch = *src++))
		if(':' == ch)
			rv++;
	return rv;
}

bool Address::setFromPresentation(const char *src, bool withPort)
{
	char ip[INET6_ADDRSTRLEN]; // INET6_ADDRSTRLEN is 46
	int port = 0;
	int family = _count_colons(src) > 1 ? AF_INET6 : AF_INET;

	if(withPort)
	{
		if(2 != sscanf(src, "[%45[0-9a-fA-F:.]]:%d", ip, &port))
		{
			if(AF_INET6 == family)
				return false;

			if(2 != sscanf(src, "%45[0-9.]:%d", ip, &port))
				return false;
		}
	}
	else
	{
		if((1 != sscanf(src, "[%45[^]]]", ip)) and (1 != sscanf(src, "%45s", ip)))
			return false;
	}

	uint8_t ipaddr[16]; // big enough for IPv6
	if(inet_pton(family, ip, ipaddr) < 1)
		return false;

	setIPAddress(ipaddr, AF_INET6 == family ? 16 : 4);

	if(withPort)
		setPort(port);

	return true;
}

} } } // namespace com::zenomt::rtmfp
