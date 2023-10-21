#pragma once

// Copyright © 2021 Michael Thornburgh
// SPDX-License-Identifier: MIT

// This module provides a semi-concrete implementation of the Cryptography Profile
// for Adobe Flash platform communication as described in Section 4 of RFC 7425.
// All cryptographic primitives are factored out and are left for subclasses to
// implement. This is to allow an implementation flexibility in choice of cryptography
// library to use (such as OpenSSL, libraries supplied natively by the runtime platform,
// ones already being used in an application, or bring-your-own). A concrete reference
// implementation using OpenSSL is provided in FlashCryptoAdapter_OpenSSL. Porting to
// other libraries using that as a guide should be straightforward.

// Section references ("§") in this module refer to RFC 7425 unless otherwise indicated.

#include "rtmfp.hpp"

namespace com { namespace zenomt { namespace rtmfp {

class HMACSHA256_Context;
class AES_Context;
class DH_Context;
class FlashCryptoKey;
class FlashCryptoCert;

enum {
	EPD_OPTION_REQUIRED_HOSTNAME = 0x00,
	EPD_OPTION_ANCILLARY_DATA    = 0x0a,
	EPD_OPTION_FINGERPRINT       = 0x0f
};

enum {
	CERT_OPTION_HOSTNAME               = 0x00,
	CERT_OPTION_ACCEPTS_ANCILLARY_DATA = 0x0a,
	CERT_OPTION_EXTRA_RANDOMNESS       = 0x0e,
	CERT_OPTION_SUPPORTED_DH_GROUP     = 0x15,
	CERT_OPTION_DH_PUBLIC_KEY          = 0x1d
};

enum {
	KEYING_OPTION_DH_PUBLIC_KEY    = 0x0d,
	KEYING_OPTION_EXTRA_RANDOMNESS = 0x0e,
	KEYING_OPTION_DH_GROUP_SELECT  = 0x1d,
	KEYING_OPTION_HMAC_NEGOTIATION = 0x1a,
	KEYING_OPTION_SSEQ_NEGOTIATION = 0x1e
};

const uint8_t KEYING_NEGOTIATE_FLAG_SND = 0x04; // Will send always
const uint8_t KEYING_NEGOTIATE_FLAG_SOR = 0x02; // Will send on request
const uint8_t KEYING_NEGOTIATE_FLAG_REQ = 0x01; // Request (actually require in this implementation)

class FlashCryptoAdapter : public ICryptoAdapter {
public:
	static const size_t FINGERPRINT_LENGTH = 32;
	static const size_t MIN_HMAC_LENGTH = 4;
	static const size_t MAX_HMAC_LENGTH = 32;
	static const size_t DEFAULT_HMAC_LENGTH = 16; // RFC 2104 §5

	FlashCryptoAdapter();

	// must be initialized before use. hostname can be NULL.
	virtual bool init(bool isServer, bool isEphemeralDH, const char *hostname);

	// convenience function calls init(isServer, isServer, hostname) as per §7 ¶2-3.
	virtual bool init(bool isServer, const char *hostname);

	bool isServer() const;
	bool isStatic() const; // Answers true if this end's certificate has static DH keys in it.

	Bytes getCanonicalEPD() const;
	Bytes getFingerprint() const;
	void  getFingerprint(void *dst) const;

	// §4.6.4 HMAC length must be between 4 and 32 inclusive.
	void   setHMACLength(size_t len);
	size_t getHMACLength() const;

	void setHMACSendAlways(bool always); // always or on-request, default on-request
	bool getHMACSendAlways() const;

	void setHMACRecvRequired(bool required);
	bool getHMACRecvRequired() const;

	void setSSeqSendAlways(bool always); // always or on-request, default on-request
	bool getSSeqSendAlways() const;

	void setSSeqRecvRequired(bool required);
	bool getSSeqRecvRequired() const;

	virtual std::shared_ptr<FlashCryptoCert> decodeFlashCertificate(const uint8_t *cert, size_t len);

	// if isServer is true and this function is set, called when the EPD contains
	// ancillary data to allow selection on, for example, aspects of an 'rtmfp:' URI.
	std::function<bool(const uint8_t *ancillary, size_t len)> isSelectedByAncillaryData;

	std::shared_ptr<SessionCryptoKey> getKeyForNewSession() override;
	Bytes getNearEncodedCertForEPD(const uint8_t *epd, size_t epdLen) override;
	bool isSelectedByEPD(const uint8_t *epd, size_t len) override;
	Bytes sign(const uint8_t *msg, size_t len, std::shared_ptr<CryptoCert> recipient) override;
	bool checkNearWinsGlare(std::shared_ptr<CryptoCert> farCert) override;
	std::shared_ptr<CryptoCert> decodeCertificate(const uint8_t *cert, size_t len) override;
	// pseudoRandomBytes to be implemented by concrete subclass
	void cryptoHash256(uint8_t *dst, const uint8_t *msg, size_t len) override; // uses sha256() method

	// convenience method uses makeHMAC_Context()
	void hmacSHA256(void *dst, const void *key, size_t keyLen, const void *msg, size_t msgLen);

	// answers false on error (all params NULL, or invalid hex at hexFingerprint), true otherwise
	static bool  makeEPD(const char *hexFingerprint, const char *ancillaryData, const char *hostname, Bytes &dst);

	// answers an empty Bytes on error (all params NULL, or invalid hex at hexFingerprint)
	static Bytes makeEPD(const char *hexFingerprint, const char *ancillaryData, const char *hostname);
	static Bytes makeEPD(const void *rawFingerprint);

	// Answer a list (in preference order) of DH groups supported. The default
	// implementation answers { 2 }. Override  to add or remove groups as supported
	// by your concrete implementation or to change the preference order. You should
	// also support groups 14 and 16. All groups listed must be supported by the DH_Context.
	virtual std::vector<int> getSupportedDHGroups() const;

	// Answer the best DH group supported by the near and far end, or -1 if there is
	// no best match. The default implementation answers the first group from
	// getSupportedDHGroups() supported by the far end, or -1. This should usually be sufficient.
	virtual int getBestDHGroup(FlashCryptoCert *farCert) const;

	// Answer true if groupID is supported, false if not. The default implementation
	// checks for groupID in getSupportedDHGroups().
	virtual bool supportsDHGroup(int groupID) const;

	// If this end has static DH keys, compute the shared secret in group given otherPublic
	// and place it at dst. Answer true on success, false on failure (including if this end
	// does not have a static key for group).
	virtual bool computeSharedSecret(int group, const void *otherPublic, size_t len, Bytes &dst) const;

	// Concrete subclass to implement
	virtual void sha256(void *dst, const void *msg, size_t len) const = 0;

	// Factories for the crypto primitives, concrete subclass to implement
	virtual std::shared_ptr<HMACSHA256_Context> makeHMAC_Context() = 0;
	virtual std::shared_ptr<AES_Context>        makeAES_Context()  = 0;
	virtual std::shared_ptr<DH_Context>         makeDH_Context()   = 0; // MUST support at least group 2.

	virtual bool defaultEncrypt_cbc(void *dst, const void *src, size_t len, uint8_t *iv);
	virtual bool defaultDecrypt_cbc(void *dst, const void *src, size_t len, uint8_t *iv);

	struct EPDParseState {
		const uint8_t *requiredHostname { nullptr };
		size_t         requiredHostnameLen { 0 };
		const uint8_t *ancillaryData { nullptr };
		size_t         ancillaryDataLen { 0 };
		const uint8_t *fingerprint { nullptr };
		size_t         fingerprintLen { 0 };

		bool parse(const uint8_t *epd, size_t len);
		// caution: members will point directly into the supplied buffer.
	};

protected:

	bool  m_isServer;
	Bytes m_encodedCert;
	bool  m_hasHostname;
	Bytes m_hostname;
	uint8_t m_fingerprint[FINGERPRINT_LENGTH];
	size_t m_hmacLength;
	bool m_hmacSendAlways;
	bool m_hmacRecvRequired;
	bool m_sseqSendAlways;
	bool m_sseqRecvRequired;

	std::map<int, std::shared_ptr<DH_Context> > m_staticDHContexts;
	std::shared_ptr<AES_Context> m_defaultEncryptContext;
	std::shared_ptr<AES_Context> m_defaultDecryptContext;
};

class HMACSHA256_Context : public Object {
public:
	// context will only be initted once
	virtual bool init(const void *key, size_t len) = 0;

	// compute() should be able to be called repeatedly to re-use the
	// same key, but it will not be called concurrently (so a computation
	// state for the key can be re-used without an expensive duplication);
	// hence no "const" qualifier.
	virtual bool compute(void *md, const void *msg, size_t len) = 0;
};

class AES_Context : public Object {
public:
	// context will only be initted once
	virtual bool init(const void *key, size_t len, bool encrypt) = 0;

	// crypt_cbc() should be able to be called repeatedly to re-use the
	// same key, but it will not be called concurrently.
	virtual bool crypt_cbc(void *dst, const void *src, size_t len, uint8_t *iv) = 0;
};

class DH_Context : public Object {
public:
	// context will only be initted once
	virtual bool init(int groupID) = 0; // must support group 2

	virtual Bytes getPublicKey() const = 0;

	// this function should be able to be called repeatedly and from multiple threads
	virtual bool computeSharedSecret(const void *otherPublic, size_t len, Bytes &dst) const = 0;
};

class FlashCryptoKey : public SessionCryptoKey {
public:
	static const uintmax_t MAX_SSEQ_GAP = 32;
	~FlashCryptoKey();

	bool init(FlashCryptoAdapter *owner);

	size_t getEncryptSrcFrontMargin() override;
	bool encrypt(uint8_t *dst, size_t &ioDstLen, uint8_t *src, size_t srcLen, size_t srcFrontMargin) override;
	bool decrypt(uint8_t *dst, size_t &ioDstLen, size_t &dstFrontMargin, const uint8_t *src, size_t srcLen) override;
	Bytes getNearNonce() override;
	Bytes getFarNonce() override;
	bool generateInitiatorKeyingComponent(std::shared_ptr<CryptoCert> responder, Bytes *outComponent) override;
	bool initiatorCombineResponderKeyingComponent(const uint8_t *responderComponent, size_t len) override;
	bool generateResponderKeyingComponent(std::shared_ptr<CryptoCert> initiator, const uint8_t *initiatorComponent, size_t len, Bytes *outComponent) override;

protected:
	void eraseSharedSecret();

	// m_dh_secret must already be computed
	bool computeKeysAndNonces(const uint8_t *sknc, size_t skncLen, const uint8_t *skfc, size_t skfcLen);

	FlashCryptoAdapter *m_owner; // weak ref
	std::atomic<bool> m_complete;
	bool m_hmacSendAlways;
	bool m_hmacRecvRequired;
	bool m_sseqSendAlways;
	bool m_sseqRecvRequired;

	uintmax_t m_txSequenceNumber;
	IndexSet m_rxSequenceNumbers;

	std::shared_ptr<DH_Context> m_dh_context;
	int     m_groupID;
	bool    m_publicKeyNeeded;
	Bytes   m_dh_secret;
	Bytes   m_sknc; // Session Key Near Component §4.6, need to remember for computing nonces
	uint8_t m_nearNonce[256/8];
	uint8_t m_farNonce[256/8];

	std::shared_ptr<AES_Context> m_txKey;
	std::shared_ptr<AES_Context> m_rxKey;

	std::shared_ptr<HMACSHA256_Context> m_txHMAC;
	size_t m_txHMACLength;

	std::shared_ptr<HMACSHA256_Context> m_rxHMAC;
	size_t m_rxHMACLength;
};

class FlashCryptoCert : public CryptoCert {
public:
	// currently owner is only used to compute the fingerprint
	bool  init(const uint8_t *cert, size_t len, FlashCryptoAdapter *owner);

	bool  isStatic() const;
	bool  doesAcceptAncillaryData() const;
	bool  supportsDHGroup(int groupID) const;
	bool  getPublicKey(int groupID, const uint8_t **publicKey, size_t *len);
	Bytes getFingerprint() const;

	void  isAuthentic(const Task &onauthentic) override;
	bool  isSelectedByEPD(const uint8_t *epd, size_t epdLen) override;
	Bytes getCanonicalEPD() override;
	void  checkSignature(const uint8_t *msg, size_t msgLen, const uint8_t *sig, size_t sigLen, const Task &ongood) override;
	bool  doesCertOverrideSession(std::shared_ptr<CryptoCert> other) override;
	Bytes encode() override;

protected:
	Bytes          m_raw;
	uint8_t        m_fingerprint[FlashCryptoAdapter::FINGERPRINT_LENGTH];
	bool           m_hasHostname :1;
	bool           m_acceptsAncillaryData :1;
	bool           m_isStatic :1;
};

} } } // namespace com::zenomt::rtmfp
