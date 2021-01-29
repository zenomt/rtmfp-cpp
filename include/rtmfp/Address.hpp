#pragma once

// Copyright © 2021 Michael Thornburgh
// SPDX-License-Identifier: MIT

#include <sys/socket.h>
#include <netinet/in.h>

#include <vector>

#include "Object.hpp"

namespace com { namespace zenomt { namespace rtmfp {

class Address : public Object {
public:
	enum Origin {
		ORIGIN_UNKNOWN  = 0,
		ORIGIN_REPORTED = 1,
		ORIGIN_OBSERVED = 2,
		ORIGIN_RELAY    = 3
	};

	static const size_t MAX_ENCODED_SIZE = 1 + 16 + 2; // flags + addr + port

	union in_sockaddr {
		struct sockaddr     s;
		struct sockaddr_in  s4;
		struct sockaddr_in6 s6;
	};
	
	Address();
	Address(const Address &other);
	Address(const struct sockaddr *addr, Origin origin = ORIGIN_UNKNOWN);

	void erase();

	void   setOrigin(Origin origin) { m_origin = origin; };
	Origin getOrigin() const        { return m_origin; };

	bool setFamily(int family);
	bool canMapToFamily(int family) const;
	int  getFamily() const { return m_addr.s.sa_family; };

	void      setPort(unsigned port);
	unsigned  getPort() const;

	size_t getIPAddressLength() const;
	const uint8_t *getIPAddressPtr() const;
	size_t getIPAddress(uint8_t *dst) const;
	std::vector<uint8_t> getIPAddress() const;

	bool setIPAddress(const uint8_t *src, size_t len);

	size_t setFromEncoding(const uint8_t *src, const uint8_t *limit);

	size_t getEncodedLength() const;
	size_t encode(uint8_t *dst) const;
	std::vector<uint8_t> encode() const;

	bool                   setSockaddr(const struct sockaddr *addr);
	const struct sockaddr *getSockaddr() const { return &m_addr.s; };
	size_t                 getSockaddrLen() const;
	static size_t          getSockaddrLen(const struct sockaddr *addr);

	Address& operator= (const Address &rhs);
	bool operator< (const Address &rhs) const;
	bool operator== (const Address &rhs) const;

	// [ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255]:65535
	static const size_t MAX_PRESENTATION_LENGTH = 54; // including terminator
	void toPresentation(char *dst, bool withPort = true) const; // dst at least MAX_PRESENTATION_LENGTH bytes
	bool setFromPresentation(const char *src, bool withPort = true);

protected:
	union in_sockaddr m_addr;
	Origin            m_origin;
};

} } } // namespace com::zenomt::rtmfp
