// Copyright © 2021 Michael Thornburgh
// SPDX-License-Identifier: MIT

#include <climits>
#include <cstring>

#include "../include/rtmfp/FlashCryptoAdapter.hpp"
#include "../include/rtmfp/Checksums.hpp"
#include "../include/rtmfp/Hex.hpp"
#include "../include/rtmfp/VLU.hpp"

namespace com { namespace zenomt { namespace rtmfp {

namespace {

// "Adobe Systems 02" in UTF-8 §4.1
const uint8_t default_session_key[16] = {
	0x41, 0x64, 0x6F, 0x62, 0x65, 0x20, 0x53, 0x79,
	0x73, 0x74, 0x65, 0x6D, 0x73, 0x20, 0x30, 0x32 };

// search for option with type_ before first marker
size_t optionSearch(const uint8_t *src, const uint8_t *limit, uintmax_t type_, const uint8_t **value, size_t *valueLen)
{
	size_t rv = 0;
	const uint8_t *cursor = src;

	while(cursor < limit)
	{
		uintmax_t eachType;
		const uint8_t *eachValue;
		size_t eachValueLen;
		size_t eachLen = Option::parse(cursor, limit, &eachType, &eachValue, &eachValueLen);
		if(0 == eachLen)
			return 0; // error
		cursor += eachLen;
		rv += eachLen;
		if(nullptr == eachValue)
			return 0;
		else if(eachType == type_)
		{
			if(value)
				*value = eachValue;
			if(valueLen)
				*valueLen = eachValueLen;
			return rv;
		}
	}

	return 0;
}

size_t optionSearch(const Bytes &src, uintmax_t type_, const uint8_t **value, size_t *valueLen)
{
	return optionSearch(src.data(), src.data() + src.size(), type_, value, valueLen);
}

size_t optionSearchForGroupAndKey(const uint8_t *src, const uint8_t *limit, uintmax_t type_, uintmax_t *groupID, const uint8_t **value, size_t *valueLen)
{
	size_t rv = 0;
	const uint8_t *optionValue;
	size_t optionValueLen;

	if(0 == (rv = optionSearch(src, limit, type_, &optionValue, &optionValueLen)))
		return 0;

	const uint8_t *optionLimit = optionValue + optionValueLen;
	size_t vluLen;
	if(0 == (vluLen = VLU::parse(optionValue, optionLimit, groupID)))
		return 0;
	optionValue += vluLen;
	optionValueLen -= vluLen;

	if(groupID and *groupID > INT_MAX)
		return 0;

	if(value)
		*value = optionValue;
	if(valueLen)
		*valueLen = optionValueLen;

	return rv;
}

bool groupOptionSearch(const uint8_t *src, const uint8_t *limit, uintmax_t type_, uintmax_t groupID, const uint8_t **value, size_t *valueLen)
{
	size_t rv = 0;
	const uint8_t *cursor = src;

	while(cursor < limit)
	{
		uintmax_t eachGroupID;

		if(0 == (rv = optionSearchForGroupAndKey(cursor, limit, type_, &eachGroupID, value, valueLen)))
			return false;
		cursor += rv;

		if(eachGroupID == groupID)
			return true;
	}

	return false;
}

bool groupOptionSearch(const Bytes &src, uintmax_t type_, uintmax_t groupID, const uint8_t **value, size_t *valueLen)
{
	return groupOptionSearch(src.data(), src.data() + src.size(), type_, groupID, value, valueLen);
}

uint8_t negotiationOptionSearch(const uint8_t *src, const uint8_t *limit, uintmax_t type_, uintmax_t *hmacLength = nullptr)
{
	const uint8_t *optionVal = nullptr;
	size_t optionValLen = 0;
	if(optionSearch(src, limit, type_, &optionVal, &optionValLen))
	{
		const uint8_t *optionLimit = optionVal + optionValLen;
		if(optionLimit > optionVal)
		{
			uint8_t rv = *optionVal++;

			if(hmacLength)
				VLU::parse(optionVal, optionLimit, hmacLength);

			return rv;
		}
	}
	return 0;
}

void appendBytesToBytes(Bytes &dst, const Bytes &src)
{
	dst.insert(dst.end(), src.begin(), src.end());
}

uint8_t negotiationFlags(bool willSendAlways, bool willSendOnRequest, bool recvRequired)
{
	return (willSendAlways ? KEYING_NEGOTIATE_FLAG_SND : 0) |
	       (willSendOnRequest ? KEYING_NEGOTIATE_FLAG_SOR : 0) |
	       (recvRequired ? KEYING_NEGOTIATE_FLAG_REQ : 0);
}

bool negotiateFlags(uint8_t flags, bool &sendAlways, bool &recvRequired)
{
	if(recvRequired and not (flags & (KEYING_NEGOTIATE_FLAG_SND | KEYING_NEGOTIATE_FLAG_SOR)))
		return false;
	if(flags & KEYING_NEGOTIATE_FLAG_SND)
		recvRequired = true;
	if(flags & KEYING_NEGOTIATE_FLAG_REQ)
		sendAlways = true;
	return true;
}


} // anonymous namespace

// --- FlashCryptoAdapter

FlashCryptoAdapter::FlashCryptoAdapter() :
	m_isServer(false),
	m_hasHostname(false),
	m_hmacLength(DEFAULT_HMAC_LENGTH),
	m_hmacSendAlways(false),
	m_hmacRecvRequired(false),
	m_sseqSendAlways(false),
	m_sseqRecvRequired(false)
{
}

bool FlashCryptoAdapter::init(bool isServer, bool isEphemeralDH, const char *hostname)
{
	m_encodedCert.clear();
	m_staticDHContexts.clear();

	m_isServer = isServer;

	m_hasHostname = hostname != NULL;
	if(hostname)
	{
		m_hostname.resize(strlen(hostname));
		memmove(m_hostname.data(), hostname, m_hostname.size());

		Option::append(CERT_OPTION_HOSTNAME, m_hostname.data(), m_hostname.size(), m_encodedCert);
	}

	if(isServer)
		Option::append(CERT_OPTION_ACCEPTS_ANCILLARY_DATA, m_encodedCert);

	auto groups = getSupportedDHGroups();

	if(isEphemeralDH)
	{
		for(auto it = groups.begin(); it != groups.end(); it++)
			Option::append(CERT_OPTION_SUPPORTED_DH_GROUP, *it, m_encodedCert);

		uint8_t randomness[64];
		pseudoRandomBytes(randomness, sizeof(randomness));
		Option::append(CERT_OPTION_EXTRA_RANDOMNESS, randomness, sizeof(randomness), m_encodedCert);
	}
	else
	{
		for(auto it = groups.begin(); it != groups.end(); it++)
		{
			auto dh = makeDH_Context();
			if(not dh->init(*it))
				return false;
			m_staticDHContexts[*it] = dh;

			Bytes pkOption;
			VLU::append(*it, pkOption);
			Bytes publicKey = dh->getPublicKey();
			pkOption.insert(pkOption.end(), publicKey.begin(), publicKey.end());
			Option::append(CERT_OPTION_DH_PUBLIC_KEY, pkOption, m_encodedCert);
		}
	}

	sha256(m_fingerprint, m_encodedCert.data(), m_encodedCert.size());

	m_defaultEncryptContext = makeAES_Context();
	m_defaultDecryptContext = makeAES_Context();
	if( (not m_defaultEncryptContext)
	 or (not m_defaultEncryptContext->init(default_session_key, sizeof(default_session_key), true))
	 or (not m_defaultDecryptContext)
	 or (not m_defaultDecryptContext->init(default_session_key, sizeof(default_session_key), false))
	)
		return false;

	return true;
}

bool FlashCryptoAdapter::init(bool isServer, const char *hostname)
{
	return init(isServer, isServer, hostname);
}

bool FlashCryptoAdapter::isServer() const
{
	return m_isServer;
}

bool FlashCryptoAdapter::isStatic() const
{
	return m_staticDHContexts.size();
}

Bytes FlashCryptoAdapter::getCanonicalEPD() const
{
	return makeEPD(m_fingerprint);
}

Bytes FlashCryptoAdapter::getFingerprint() const
{
	return Bytes(m_fingerprint, m_fingerprint + sizeof(m_fingerprint));
}

void FlashCryptoAdapter::getFingerprint(void *dst) const
{
	memmove(dst, m_fingerprint, sizeof(m_fingerprint));
}

void FlashCryptoAdapter::setHMACLength(size_t len)
{
	if(len < MIN_HMAC_LENGTH)
		len = MIN_HMAC_LENGTH;
	if(len > MAX_HMAC_LENGTH)
		len = MAX_HMAC_LENGTH;
	m_hmacLength = len;
}

size_t FlashCryptoAdapter::getHMACLength() const
{
	return m_hmacLength;
}

void FlashCryptoAdapter::setHMACSendAlways(bool always)
{
	m_hmacSendAlways = always;
}

bool FlashCryptoAdapter::getHMACSendAlways() const
{
	return m_hmacSendAlways;
}

void FlashCryptoAdapter::setHMACRecvRequired(bool required)
{
	m_hmacRecvRequired = required;
}

bool FlashCryptoAdapter::getHMACRecvRequired() const
{
	return m_hmacRecvRequired;
}

void FlashCryptoAdapter::setSSeqSendAlways(bool always)
{
	m_sseqSendAlways = always;
}

bool FlashCryptoAdapter::getSSeqSendAlways() const
{
	return m_sseqSendAlways;
}

void FlashCryptoAdapter::setSSeqRecvRequired(bool required)
{
	m_sseqRecvRequired = required;
}

bool FlashCryptoAdapter::getSSeqRecvRequired() const
{
	return m_sseqRecvRequired;
}

std::shared_ptr<FlashCryptoCert> FlashCryptoAdapter::decodeFlashCertificate(const uint8_t *cert, size_t len)
{
	auto rv = share_ref(new FlashCryptoCert(), false);
	if(not rv->init(cert, len, this))
		rv.reset();
	return rv;
}

std::shared_ptr<SessionCryptoKey> FlashCryptoAdapter::getKeyForNewSession()
{
	auto rv = share_ref(new FlashCryptoKey(), false);
	if(not rv->init(this))
		rv.reset();
	return rv;
}

Bytes FlashCryptoAdapter::getNearEncodedCertForEPD(const uint8_t *epd, size_t epdLen)
{
	return m_encodedCert;
}

bool FlashCryptoAdapter::isSelectedByEPD(const uint8_t *epdBytes, size_t len)
{
	EPDParseState epd;
	if(not epd.parse(epdBytes, len))
		return false;

	if(epd.fingerprint)
		return (sizeof(m_fingerprint) == epd.fingerprintLen) and (0 == memcmp(epd.fingerprint, m_fingerprint, sizeof(m_fingerprint)));

	if(epd.requiredHostname)
	{
		if((not m_hasHostname) or (epd.requiredHostnameLen != m_hostname.size()) or memcmp(m_hostname.data(), epd.requiredHostname, epd.requiredHostnameLen))
			return false;
	}

	if(epd.ancillaryData)
	{
		if(not m_isServer)
			return false;

		if(isSelectedByAncillaryData and not isSelectedByAncillaryData(epd.ancillaryData, epd.ancillaryDataLen))
			return false;
	}

	// epd.parse would have failed if there wasn't at least one of fingerprint, hostname, or ancillary data.
	return true;
}

Bytes FlashCryptoAdapter::sign(const uint8_t *msg, size_t len, std::shared_ptr<CryptoCert> recipient)
{
	return Bytes(1, 'X');
}

bool FlashCryptoAdapter::checkNearWinsGlare(std::shared_ptr<CryptoCert> farCert)
{
	return not (farCert->encode() < m_encodedCert); // §4.3.6
}

std::shared_ptr<CryptoCert> FlashCryptoAdapter::decodeCertificate(const uint8_t *cert, size_t len)
{
	return decodeFlashCertificate(cert, len);
}

void FlashCryptoAdapter::cryptoHash256(uint8_t *dst, const uint8_t *msg, size_t len)
{
	sha256(dst, msg, len);
}

void FlashCryptoAdapter::hmacSHA256(void *dst, const void *key, size_t keyLen, const void *msg, size_t msgLen)
{
	auto ctx = makeHMAC_Context();
	ctx->init(key, keyLen);
	ctx->compute(dst, msg, msgLen);
}

bool FlashCryptoAdapter::makeEPD(const char *hexFingerprint, const char *ancillaryData, const char *hostname, Bytes &dst)
{
	if((not hexFingerprint) and (not ancillaryData) and (not hostname))
		return false;

	if(hexFingerprint)
	{
		Bytes tmp;
		if(not Hex::decode(hexFingerprint, tmp))
			return false;
		Option::append(EPD_OPTION_FINGERPRINT, tmp.data(), tmp.size(), dst);
	}

	if(ancillaryData)
		Option::append(EPD_OPTION_ANCILLARY_DATA, ancillaryData, strlen(ancillaryData), dst);

	if(hostname)
		Option::append(EPD_OPTION_REQUIRED_HOSTNAME, hostname, strlen(hostname), dst);

	return true;
}

Bytes FlashCryptoAdapter::makeEPD(const char *hexFingerprint, const char *ancillaryData, const char *hostname)
{
	Bytes rv;
	makeEPD(hexFingerprint, ancillaryData, hostname, rv);
	return rv;
}

Bytes FlashCryptoAdapter::makeEPD(const void *rawFingerprint)
{
	Bytes rv;
	Option::append(EPD_OPTION_FINGERPRINT, rawFingerprint, FINGERPRINT_LENGTH, rv);
	return rv;
}

std::vector<int> FlashCryptoAdapter::getSupportedDHGroups() const
{
	std::vector<int> rv;
	rv.push_back(2);
	return rv;
}

int FlashCryptoAdapter::getBestDHGroup(FlashCryptoCert *farCert) const
{
	auto groups = getSupportedDHGroups();
	for(auto it = groups.begin(); it != groups.end(); it++)
		if(farCert->supportsDHGroup(*it))
			return *it;
	return -1;
}

bool FlashCryptoAdapter::supportsDHGroup(int groupID) const
{
	auto groups = getSupportedDHGroups();
	for(auto it = groups.begin(); it != groups.end(); it++)
		if(groupID == *it)
			return true;
	return false;
}

bool FlashCryptoAdapter::computeSharedSecret(int group, const void *otherPublic, size_t len, Bytes &dst) const
{
	auto it = m_staticDHContexts.find(group);
	if(it == m_staticDHContexts.end())
		return false;
	return it->second->computeSharedSecret(otherPublic, len, dst);
}

bool FlashCryptoAdapter::defaultEncrypt_cbc(const void *dst, const void *src, size_t len, uint8_t *iv)
{
	return m_defaultEncryptContext->crypt_cbc(dst, src, len, iv);
}

bool FlashCryptoAdapter::defaultDecrypt_cbc(const void *dst, const void *src, size_t len, uint8_t *iv)
{
	return m_defaultDecryptContext->crypt_cbc(dst, src, len, iv);
}

bool FlashCryptoAdapter::EPDParseState::parse(const uint8_t *epd, size_t len)
{
	fingerprint = ancillaryData = requiredHostname = NULL;
	fingerprintLen = ancillaryDataLen = requiredHostnameLen = 0;

	size_t rv;
	const uint8_t *cursor = epd;
	const uint8_t *limit = epd + len;

	while(cursor < limit)
	{
		uintmax_t optionType;
		const uint8_t *value;
		size_t valueLen;

		rv = Option::parse(cursor, limit, &optionType, &value, &valueLen);
		if(0 == rv)
			return false;
		cursor += rv;

		if(NULL == value)
			continue;

		switch(optionType)
		{
		case EPD_OPTION_REQUIRED_HOSTNAME:
			requiredHostname = value;
			requiredHostnameLen = valueLen;
			break;
		case EPD_OPTION_ANCILLARY_DATA:
			ancillaryData = value;
			ancillaryDataLen = valueLen;
			break;
		case EPD_OPTION_FINGERPRINT:
			fingerprint = value;
			fingerprintLen = valueLen;
			break;
		}
	}

	return fingerprint or ancillaryData or requiredHostname;
}

// --- FlashCryptoKey

FlashCryptoKey::~FlashCryptoKey()
{
	eraseSharedSecret();
	memset(m_nearNonce, 0xff, sizeof(m_nearNonce));
	memset(m_farNonce, 0xff, sizeof(m_farNonce));
}

bool FlashCryptoKey::init(FlashCryptoAdapter *owner)
{
	m_owner = owner;
	m_complete = false;
	m_hmacSendAlways = owner->getHMACSendAlways();
	m_hmacRecvRequired = owner->getHMACRecvRequired();
	m_sseqSendAlways = owner->getSSeqSendAlways();
	m_sseqRecvRequired = owner->getSSeqRecvRequired();
	m_txSequenceNumber = 0;
	m_groupID = -1;
	m_publicKeyNeeded = false;
	m_txHMACLength = owner->getHMACLength();
	m_rxHMACLength = 0;

	return true;
}

size_t FlashCryptoKey::getEncryptSrcFrontMargin()
{
	if(not m_complete)
		return 2;

	size_t rv = m_hmacSendAlways ? 0 : 2;
	if(m_sseqSendAlways)
		rv += VLU::encode(m_txSequenceNumber, nullptr);

	return rv;
}

bool FlashCryptoKey::encrypt(uint8_t *dst, size_t &ioDstLen, uint8_t *src, size_t srcLen, size_t srcFrontMargin)
{
	bool complete = m_complete;
	bool useSSeq = complete and m_sseqSendAlways;
	bool useHMAC = complete and m_hmacSendAlways;
	size_t hmacLen = useHMAC ? m_txHMACLength : 0;

	if(srcLen & 0xf) // do we need padding?
	{
		size_t paddingLen = 16 - (srcLen & 0xf);
		if(ioDstLen < srcLen + paddingLen + FlashCryptoAdapter::MAX_HMAC_LENGTH)
			return false;
		memset(src + srcLen, 0xff, paddingLen);
		srcLen += paddingLen;
	}
	else if(ioDstLen < srcLen + FlashCryptoAdapter::MAX_HMAC_LENGTH)
		return false;

	uint8_t *cursor = src;
	if(useSSeq)
		cursor += VLU::encode(m_txSequenceNumber++, cursor);
	if(not useHMAC)
	{
		uint16_t cksum = in_cksum(src + srcFrontMargin, srcLen - srcFrontMargin);
		*cursor++ = cksum >> 8;
		*cursor++ = cksum & 0xff;
	}

	uint8_t iv[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
	if(complete)
	{
		if(not m_txKey->crypt_cbc(dst, src, srcLen, iv))
			return false;
	}
	else if(not m_owner->defaultEncrypt_cbc(dst, src, srcLen, iv))
		return false;

	if(useHMAC and not m_txHMAC->compute(dst + srcLen, dst, srcLen))
		return false;

	ioDstLen = srcLen + hmacLen;
	return true;
}

bool FlashCryptoKey::decrypt(uint8_t *dst, size_t &ioDstLen, size_t &dstFrontMargin, const uint8_t *src, size_t srcLen)
{
	bool complete = m_complete;
	bool useSSeq = complete and m_sseqRecvRequired;
	bool useHMAC = complete and m_hmacRecvRequired;
	size_t hmacLen = useHMAC ? m_rxHMACLength : 0;

	if((ioDstLen + hmacLen < srcLen) or (srcLen < hmacLen))
		return false;

	srcLen -= hmacLen;
	if((srcLen & 0xf) or not srcLen)
		return false;

	if(useHMAC)
	{
		uint8_t md[FlashCryptoAdapter::MAX_HMAC_LENGTH];
		if(not m_rxHMAC->compute(md, src, srcLen))
			return false;
		if(memcmp(md, src + srcLen, hmacLen))
			return false;
	}

	uint8_t iv[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
	if(complete)
	{
		if(not m_rxKey->crypt_cbc(dst, src, srcLen, iv))
			return false;
	}
	else if(not m_owner->defaultDecrypt_cbc(dst, src, srcLen, iv))
		return false;

	size_t rv;
	uint8_t *cursor = dst;
	const uint8_t *limit = cursor + srcLen;
	uintmax_t sequenceNumber = 0;
	if(useSSeq)
	{
		if(0 == (rv = VLU::parse(dst, limit, &sequenceNumber)))
			return false;
		cursor += rv;

		if(m_rxSequenceNumbers.contains(sequenceNumber))
			return false;
	}

	if(not useHMAC)
	{
		if(limit - cursor < 2)
			return false;
		uint16_t cksum_field = (cursor[0] << 8) + cursor[1];
		cursor += 2;

		if(cksum_field != in_cksum(cursor, limit - cursor))
			return false;
	}

	if(useSSeq)
	{
		m_rxSequenceNumbers.add(sequenceNumber);
		if(sequenceNumber > MAX_SSEQ_GAP)
			m_rxSequenceNumbers.add(0, sequenceNumber - MAX_SSEQ_GAP);
	}

	ioDstLen = srcLen;
	dstFrontMargin = cursor - dst;

	return true;
}

Bytes FlashCryptoKey::getNearNonce()
{
	return Bytes(m_nearNonce, m_nearNonce + sizeof(m_nearNonce));
}

Bytes FlashCryptoKey::getFarNonce()
{
	return Bytes(m_farNonce, m_farNonce + sizeof(m_farNonce));
}

bool FlashCryptoKey::generateInitiatorKeyingComponent(std::shared_ptr<CryptoCert> responder_, Bytes *outComponent)
{
	FlashCryptoCert *responder = (FlashCryptoCert *)(responder_.get());

	m_sknc.clear();

	m_groupID = m_owner->getBestDHGroup(responder);
	if(m_groupID < 0)
		return false;

	if(m_owner->isStatic())
	{
		Option::append(KEYING_OPTION_DH_GROUP_SELECT, m_groupID, m_sknc);

		uint8_t extraRandomness[512/8]; // SHA256 block size
		m_owner->pseudoRandomBytes(extraRandomness, sizeof(extraRandomness));
		Option::append(KEYING_OPTION_EXTRA_RANDOMNESS, extraRandomness, sizeof(extraRandomness), m_sknc);
	}
	else
	{
		m_dh_context = m_owner->makeDH_Context();
		if((not m_dh_context) or not m_dh_context->init(m_groupID))
			return false;
		Bytes buf;
		VLU::append(m_groupID, buf);
		appendBytesToBytes(buf, m_dh_context->getPublicKey());
		Option::append(KEYING_OPTION_DH_PUBLIC_KEY, buf, m_sknc);
	}

	if(responder->isStatic())
	{
		const uint8_t *publicKey = nullptr;
		size_t publicKeyLen = 0;
		if(not responder->getPublicKey(m_groupID, &publicKey, &publicKeyLen)) // should be impossible
			return false;
		if(m_dh_context)
		{
			if(not m_dh_context->computeSharedSecret(publicKey, publicKeyLen, m_dh_secret))
				return false;
			m_dh_context.reset();
		}
		else if(not m_owner->computeSharedSecret(m_groupID, publicKey, publicKeyLen, m_dh_secret))
			return false;
	}
	else
		m_publicKeyNeeded = true;

	Bytes hmacNegotiation;
	hmacNegotiation.push_back(negotiationFlags(m_hmacSendAlways, true, m_hmacRecvRequired));
	VLU::append(m_txHMACLength, hmacNegotiation);
	Option::append(KEYING_OPTION_HMAC_NEGOTIATION, hmacNegotiation, m_sknc);

	uint8_t sseqFlags = negotiationFlags(m_sseqSendAlways, true, m_sseqRecvRequired);
	Option::append(KEYING_OPTION_SSEQ_NEGOTIATION, &sseqFlags, 1, m_sknc);

	*outComponent = m_sknc;

	return true;
}

bool FlashCryptoKey::initiatorCombineResponderKeyingComponent(const uint8_t *responderComponent, size_t len)
{
	const uint8_t *componentLimit = responderComponent + len;

	// try to fail on cheaper stuff first

	uint8_t sseqFlags = negotiationOptionSearch(responderComponent, componentLimit, KEYING_OPTION_SSEQ_NEGOTIATION);
	if(not negotiateFlags(sseqFlags, m_sseqSendAlways, m_sseqRecvRequired))
		return false;

	uintmax_t hmacRxLen = 0; // an illegal value if receive is required
	uint8_t hmacFlags = negotiationOptionSearch(responderComponent, componentLimit, KEYING_OPTION_HMAC_NEGOTIATION, &hmacRxLen);
	if(not negotiateFlags(hmacFlags, m_hmacSendAlways, m_hmacRecvRequired))
		return false;
	if(m_hmacRecvRequired)
	{
		if((hmacRxLen < FlashCryptoAdapter::MIN_HMAC_LENGTH) or (hmacRxLen > FlashCryptoAdapter::MAX_HMAC_LENGTH))
			return false;
		m_rxHMACLength = hmacRxLen;
	}

	if(m_publicKeyNeeded)
	{
		eraseSharedSecret(); // just in case

		const uint8_t *publicKey = nullptr;
		size_t publicKeyLen = 0;
		if(not groupOptionSearch(responderComponent, componentLimit, KEYING_OPTION_DH_PUBLIC_KEY, m_groupID, &publicKey, &publicKeyLen))
			return false;
		if(m_dh_context)
		{
			if(not m_dh_context->computeSharedSecret(publicKey, publicKeyLen, m_dh_secret))
				return false;
		}
		else if(not m_owner->computeSharedSecret(m_groupID, publicKey, publicKeyLen, m_dh_secret))
			return false;
	}
	// else we already computed the DH shared secret from a public key in their certificate

	// this should always succeeed unless something terrible is happening
	if(not computeKeysAndNonces(m_sknc.data(), m_sknc.size(), responderComponent, len))
		return false;

	eraseSharedSecret();
	m_dh_context.reset();

	m_complete = true;

	return true;
}

bool FlashCryptoKey::generateResponderKeyingComponent(std::shared_ptr<CryptoCert> initiator_, const uint8_t *initiatorComponent, size_t len, Bytes *outComponent)
{
	FlashCryptoCert *initiator = (FlashCryptoCert *)(initiator_.get());
	const uint8_t *componentLimit = initiatorComponent + len;

	Bytes sknc; // don't need to save this for later in m_sknc

	// try to fail on cheaper stuff first before doing expensive DH computation

	uint8_t sseqFlags_i = negotiationOptionSearch(initiatorComponent, componentLimit, KEYING_OPTION_SSEQ_NEGOTIATION);
	if(not negotiateFlags(sseqFlags_i, m_sseqSendAlways, m_sseqRecvRequired))
		return false;

	uint8_t sseqFlags_r = negotiationFlags(m_sseqSendAlways, true, m_sseqRecvRequired);
	Option::append(KEYING_OPTION_SSEQ_NEGOTIATION, &sseqFlags_r, 1, sknc);

	uintmax_t hmacRxLen = 0;
	uint8_t hmacFlags_i = negotiationOptionSearch(initiatorComponent, componentLimit, KEYING_OPTION_HMAC_NEGOTIATION, &hmacRxLen);
	if(not negotiateFlags(hmacFlags_i, m_hmacSendAlways, m_hmacRecvRequired))
		return false;
	if(m_hmacRecvRequired)
	{
		if((hmacRxLen < FlashCryptoAdapter::MIN_HMAC_LENGTH) or (hmacRxLen > FlashCryptoAdapter::MAX_HMAC_LENGTH))
			return false;
		m_rxHMACLength = hmacRxLen;
	}

	Bytes hmacNegotiation_r;
	hmacNegotiation_r.push_back(negotiationFlags(m_hmacSendAlways, true, m_hmacRecvRequired));
	VLU::append(m_txHMACLength, hmacNegotiation_r);
	Option::append(KEYING_OPTION_HMAC_NEGOTIATION, hmacNegotiation_r, sknc);

	const uint8_t *publicKey = nullptr;
	size_t publicKeyLen = 0;
	uintmax_t groupID = 0;
	if(initiator->isStatic())
	{
		if(0 == optionSearchForGroupAndKey(initiatorComponent, componentLimit, KEYING_OPTION_DH_GROUP_SELECT, &groupID, nullptr, nullptr))
			return false;
		if(not initiator->getPublicKey((int)groupID, &publicKey, &publicKeyLen))
			return false;
	}
	else
	{
		if(0 == optionSearchForGroupAndKey(initiatorComponent, componentLimit, KEYING_OPTION_DH_PUBLIC_KEY, &groupID, &publicKey, &publicKeyLen))
			return false;
	}

	m_groupID = (int)groupID;
	if(not m_owner->supportsDHGroup(m_groupID))
		return false;

	if(m_owner->isStatic())
	{
		if(not m_owner->computeSharedSecret(m_groupID, publicKey, publicKeyLen, m_dh_secret))
			return false;

		uint8_t extraRandomness[512/8]; // SHA256 block size
		m_owner->pseudoRandomBytes(extraRandomness, sizeof(extraRandomness));
		Option::append(KEYING_OPTION_EXTRA_RANDOMNESS, extraRandomness, sizeof(extraRandomness), sknc);
	}
	else
	{
		auto dhContext = m_owner->makeDH_Context();
		if((not dhContext) or not dhContext->init(m_groupID))
			return false;
		if(not dhContext->computeSharedSecret(publicKey, publicKeyLen, m_dh_secret))
			return false;

		Bytes buf;
		VLU::append(m_groupID, buf);
		appendBytesToBytes(buf, dhContext->getPublicKey());
		Option::append(KEYING_OPTION_DH_PUBLIC_KEY, buf, sknc);
	}

	if(not computeKeysAndNonces(sknc.data(), sknc.size(), initiatorComponent, len))
		return false;

	eraseSharedSecret();
	m_dh_context.reset();

	*outComponent = sknc;
	m_complete = true;

	return true;
}

void FlashCryptoKey::eraseSharedSecret()
{
	memset(m_dh_secret.data(), 0, m_dh_secret.size());
	memset(m_dh_secret.data(), 0xff, m_dh_secret.size());
	m_dh_secret.clear();
}

bool FlashCryptoKey::computeKeysAndNonces(const uint8_t *sknc, size_t skncLen, const uint8_t *skfc, size_t skfcLen)
{
	uint8_t encrypt_key[256/8];
	uint8_t decrypt_key[256/8];
	uint8_t md[256/8];

	m_owner->hmacSHA256(m_nearNonce, m_dh_secret.data(), m_dh_secret.size(), sknc, skncLen);
	m_owner->hmacSHA256(m_farNonce, m_dh_secret.data(), m_dh_secret.size(), skfc, skfcLen);

	m_owner->hmacSHA256(md, skfc, skfcLen, sknc, skncLen);
	m_owner->hmacSHA256(encrypt_key, m_dh_secret.data(), m_dh_secret.size(), md, sizeof(md));

	m_owner->hmacSHA256(md, sknc, skncLen, skfc, skfcLen);
	m_owner->hmacSHA256(decrypt_key, m_dh_secret.data(), m_dh_secret.size(), md, sizeof(md));

	m_txKey = m_owner->makeAES_Context();
	if((not m_txKey) or not m_txKey->init(encrypt_key, 128/8, true))
		return false;

	m_rxKey = m_owner->makeAES_Context();
	if((not m_rxKey) or not m_rxKey->init(decrypt_key, 128/8, false))
		return false;

	if(m_hmacSendAlways)
	{
		m_owner->hmacSHA256(md, m_dh_secret.data(), m_dh_secret.size(), encrypt_key, sizeof(encrypt_key));
		m_txHMAC = m_owner->makeHMAC_Context();
		if((not m_txHMAC) or not m_txHMAC->init(md, sizeof(md)))
			return false;
	}

	if(m_hmacRecvRequired)
	{
		m_owner->hmacSHA256(md, m_dh_secret.data(), m_dh_secret.size(), decrypt_key, sizeof(decrypt_key));
		m_rxHMAC = m_owner->makeHMAC_Context();
		if((not m_rxHMAC) or not m_rxHMAC->init(md, sizeof(md)))
			return false;
	}

	return true;
}

// --- FlashCryptoCert

bool FlashCryptoCert::init(const uint8_t *cert, size_t len, FlashCryptoAdapter *owner)
{
	m_raw.assign(cert, cert + len);
	m_hasHostname = false;
	m_acceptsAncillaryData = false;
	m_isStatic = false;

	bool isEphemeral = false;
	bool markerFound = false;
	size_t canonicalLength = 0;
	const uint8_t *cursor = cert;
	const uint8_t *limit = cursor + len;

	while(cursor < limit)
	{
		uintmax_t optionType;
		const uint8_t *value;
		size_t rv;
		if(0 == (rv = Option::parse(cursor, limit, &optionType, &value, nullptr)))
			return false;
		cursor += rv;
		if(not markerFound)
			canonicalLength += rv;
		if(NULL == value)
		{
			markerFound = true;
			continue;
		}

		if(not markerFound)
		{
			switch(optionType)
			{
			case CERT_OPTION_HOSTNAME: m_hasHostname = true; break;
			case CERT_OPTION_ACCEPTS_ANCILLARY_DATA: m_acceptsAncillaryData = true; break;
			case CERT_OPTION_SUPPORTED_DH_GROUP: isEphemeral = true; break;
			case CERT_OPTION_DH_PUBLIC_KEY: m_isStatic = true; break;
			default: break;
			}
		}
	}

	owner->sha256(m_fingerprint, m_raw.data(), canonicalLength);

	return m_isStatic != isEphemeral;
}

bool FlashCryptoCert::isStatic() const
{
	return m_isStatic;
}

bool FlashCryptoCert::doesAcceptAncillaryData() const
{
	return m_acceptsAncillaryData;
}

bool FlashCryptoCert::supportsDHGroup(int groupID) const
{
	return groupOptionSearch(m_raw, isStatic() ? CERT_OPTION_DH_PUBLIC_KEY : CERT_OPTION_SUPPORTED_DH_GROUP, groupID, nullptr, nullptr);
}

bool FlashCryptoCert::getPublicKey(int groupID, const uint8_t **publicKey, size_t *len)
{
	return isStatic() and groupOptionSearch(m_raw, CERT_OPTION_DH_PUBLIC_KEY, groupID, publicKey, len);
}

Bytes FlashCryptoCert::getFingerprint() const
{
	return Bytes(m_fingerprint, m_fingerprint + sizeof(m_fingerprint));
}

void FlashCryptoCert::isAuthentic(const Task &onauthentic)
{
	onauthentic();
}

bool FlashCryptoCert::isSelectedByEPD(const uint8_t *epdBytes, size_t epdLen)
{
	FlashCryptoAdapter::EPDParseState epd;
	if(not epd.parse(epdBytes, epdLen))
		return false;

	// epd has at least one of fingerprint, required hostname, or ancillary data

	if(epd.fingerprint)
		return (sizeof(m_fingerprint) == epd.fingerprintLen) and (0 == memcmp(epd.fingerprint, m_fingerprint, sizeof(m_fingerprint)));

	if(epd.requiredHostname)
	{
		if(not m_hasHostname)
			return false;

		const uint8_t *hostname;
		size_t hostnameLen;
		if(0 == optionSearch(m_raw, CERT_OPTION_HOSTNAME, &hostname, &hostnameLen))
			return false;
		if((hostnameLen != epd.requiredHostnameLen) or memcmp(hostname, epd.requiredHostname, hostnameLen))
			return false;
	}

	if(epd.ancillaryData and not m_acceptsAncillaryData)
		return false;

	return true;
}

Bytes FlashCryptoCert::getCanonicalEPD()
{
	return FlashCryptoAdapter::makeEPD(m_fingerprint);
}

void FlashCryptoCert::checkSignature(const uint8_t *msg, size_t msgLen, const uint8_t *sig, size_t sigLen, const Task &ongood)
{
	// signatures are not required. TODO: support Simple Password scheme someday §4.3.5.1.1
	ongood();
}

bool FlashCryptoCert::doesCertOverrideSession(std::shared_ptr<CryptoCert> other)
{
	return m_raw == other->encode(); // §4.3.7
}

Bytes FlashCryptoCert::encode()
{
	return m_raw;
}

} } } // namespace com::zenomt::rtmfp
