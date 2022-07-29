// Copyright © 2021 Michael Thornburgh
// SPDX-License-Identifier: MIT

#include "../include/rtmfp/PlainCryptoAdapter.hpp"
#include "../include/rtmfp/Checksums.hpp"

#include <cstdlib>
#include <cstring>
#include <ctime>

namespace com { namespace zenomt { namespace rtmfp {

namespace {

Bytes u16_bytes(uint16_t n)
{
	Bytes rv;
	rv.push_back(n >> 8);
	rv.push_back(n & 0xff);
	return rv;
}

class PlainCryptoKey : public SessionCryptoKey {
public:
	PlainCryptoKey() : m_txSalt(0), m_complete(false)
	{
		m_rxSalt = rand();
	}

	size_t getEncryptSrcFrontMargin() override
	{
		return 16; // to test front margin
	}

	bool encrypt(uint8_t *dst, size_t &ioDstLen, uint8_t *src, size_t srcLen, size_t srcFrontMargin) override
	{
		if(srcFrontMargin > srcLen)
			return false;

		src += srcFrontMargin;
		srcLen -= srcFrontMargin;
		memset(src + srcLen, 0xff, 16); // pad end of packet
		srcLen += 16;
		uint16_t cksum = in_cksum(src, srcLen) + (m_complete ? m_txSalt : 0);
		src[srcLen++] = cksum >> 8;
		src[srcLen++] = cksum & 0xff;

		if(ioDstLen < srcLen)
			return false;
		memmove(dst, src, srcLen);

		ioDstLen = srcLen;

		return true;
	}

	bool decrypt(uint8_t *dst, size_t &ioDstLen, size_t &dstFrontMargin, const uint8_t *src, size_t srcLen) override
	{
		if(srcLen < 2)
			return false;

		if(ioDstLen < srcLen + 16 - 2)
			return false;

		uint16_t cksum = (src[srcLen - 2] << 8) + src[srcLen - 1] - (m_complete ? m_rxSalt : 0);
		if(in_cksum(src, srcLen - 2) != cksum)
			return false;

		dstFrontMargin = 16;
		memmove(dst + dstFrontMargin, src, srcLen - 2);
		ioDstLen = srcLen + dstFrontMargin - 2;

		return true;
	}

	Bytes getNearNonce() override
	{
		return u16_bytes(m_rxSalt);
	}

	Bytes getFarNonce() override
	{
		return u16_bytes(m_txSalt);
	}

	bool generateInitiatorKeyingComponent(std::shared_ptr<CryptoCert> responder, Bytes *outComponent) override
	{
		*outComponent = u16_bytes(m_rxSalt);
		return true;
	}

	bool initiatorCombineResponderKeyingComponent(const uint8_t *responderComponent, size_t len) override
	{
		if(len < 2)
			return false;
		m_txSalt = (responderComponent[0] << 8) + responderComponent[1];
		m_complete = true;
		return true;
	}

	bool generateResponderKeyingComponent(std::shared_ptr<CryptoCert> initiator, const uint8_t *initiatorComponent, size_t len, Bytes *outComponent) override
	{
		if(len < 2)
			return false;
		*outComponent = u16_bytes(m_rxSalt);
		m_txSalt = (initiatorComponent[0] << 8) + initiatorComponent[1];
		m_complete = true;
		return true;
	}

protected:
	uint16_t m_txSalt;
	uint16_t m_rxSalt;
	bool     m_complete;
};

class PlainCryptoCert : public CryptoCert {
public:
	PlainCryptoCert(const uint8_t *bytes, size_t len) : m_identity(bytes, bytes + len) {}

	void isAuthentic(const Task &onauthentic) override
	{
		if(m_identity.size() > 0)
			onauthentic();
	}

	bool isSelectedByEPD(const uint8_t *bytes, size_t len) override
	{
		return (len == m_identity.size()) and (0 == memcmp(bytes, m_identity.data(), len));
	}

	Bytes getCanonicalEPD() override
	{
		return m_identity;
	}

	void checkSignature(const uint8_t *msg, size_t msgLen, const uint8_t *sig, size_t sigLen, const Task &ongood) override
	{
		ongood();
	}

	bool doesCertOverrideSession(std::shared_ptr<CryptoCert> other_) override
	{
		PlainCryptoCert *other = (PlainCryptoCert *)other_.get();
		return m_identity == other->m_identity;
	}

	Bytes encode() override
	{
		return m_identity;
	}

	Bytes m_identity;
};

} // anonymous namespace

PlainCryptoAdapter::PlainCryptoAdapter(const char *identity)
{
	const uint8_t *bytes = (uint8_t *)identity;
	m_identity = Bytes(bytes, bytes + strlen(identity));
}

std::shared_ptr<SessionCryptoKey> PlainCryptoAdapter::getKeyForNewSession()
{
	return share_ref(new PlainCryptoKey(), false);
}

Bytes PlainCryptoAdapter::getNearEncodedCertForEPD(const uint8_t *epd, size_t epdLen)
{
	return m_identity;
}

bool PlainCryptoAdapter::isSelectedByEPD(const uint8_t *bytes, size_t len)
{
	return (len == m_identity.size()) and (0 == memcmp(bytes, m_identity.data(), len));
}

Bytes PlainCryptoAdapter::sign(const uint8_t *msg, size_t msgLen, std::shared_ptr<CryptoCert> recipient)
{
	return Bytes(1, 'X');
}

bool PlainCryptoAdapter::checkNearWinsGlare(std::shared_ptr<CryptoCert> farCert)
{
	return m_identity < ((PlainCryptoCert *)farCert.get())->m_identity;
}

std::shared_ptr<CryptoCert> PlainCryptoAdapter::decodeCertificate(const uint8_t *bytes, size_t len)
{
	return share_ref(new PlainCryptoCert(bytes, len), false);
}

void PlainCryptoAdapter::pseudoRandomBytes(uint8_t *dst, size_t len)
{
	while(len-- > 0)
		*dst++ = rand() & 0xff;
}

void PlainCryptoAdapter::cryptoHash256(uint8_t *dst, const uint8_t *msg, size_t len)
{
	uint32_t rv[8];

	uint32_t crc = ~crc32_le(msg, len); // NOT cryptographic
	for(int x = 0; x < 8; x++)
		rv[x] = crc;

	memmove(dst, rv, sizeof(rv));
}

} } }
