#pragma once

#include "rtmfp.hpp"

namespace com { namespace zenomt { namespace rtmfp {

class HMACSHA256_Context;
class AES_Context;
class DH_Context;

class FlashCryptoAdapter : public ICryptoAdapter {
public:
	FlashCryptoAdapter(bool isServer, const char *hostname);
	FlashCryptoAdapter() = delete;
	~FlashCryptoAdapter();

	// HMAC length must be between 4 and 32 inclusive, §4.6.4. Default 16 (RFC 2104 §5).
	void   setHMACLength(size_t len);
	size_t getHMACLength();

	void setHMACSendMode(bool always); // always or on-request, default on-request
	bool getHMACSendMode();

	void setHMACRecvMode(bool require);
	bool getHMACRecvMode();

	void setSSeqSendMode(bool always); // always or on-request, default on-request
	bool getSSeqSendMode();

	void setSSeqRecvMode(bool require);
	bool getSSeqRecvMode();

	std::shared_ptr<SessionCryptoKey> getKeyForNewSession() override;
	Bytes getNearEncodedCertForEPD(const uint8_t *epd, size_t epdLen) override;
	bool isSelectedByEPD(const uint8_t *epd, size_t len) override;
	Byte sign(const uint8_t *msg, size_t len, std::shared_ptr<CryptoCert> recipient) override;
	bool checkNearWinsGlare(std::shared_ptr<CryptoCert> far) override;
	std::shared_ptr<CryptoCert> decodeCertificate(const uint8_t *cert, size_t len) override;
	// pseudoRandomBytes to be implemented by concrete subclass
	void cryptoHash256(uint8_t *dst, const uint8_t *msg, size_t len) override; // uses sha256() method

	// convenience method uses makeHMAC_Context()
	void hmacSHA256(void *dst, const void *key, size_t keyLen, const void *msg, size_t msgLen)

	// concrete subclass to implement
	virtual void sha256(void *dst, const void *msg, size_t len) = 0;

protected:
	// factories for the crypto primitives, concrete subclass to implement
	virtual std::shared_ptr<HMACSHA256_Context> makeHMAC_Context() const = 0;
	virtual std::shared_ptr<AES_Context>        makeAES_Context()  const = 0;
	virtual std::shared_ptr<DH_Context>         makeDH_Context()   const = 0;
};

class HMACSHA256_Context : public Object {
public:
	virtual bool init(const void *key, size_t len) = 0;
	virtual bool compute(uint8_t *md, const void *msg, size_t len) const = 0;
};

class AES_Context : public Object {
public:
	virtual bool init(const void *key, size_t len, bool encrypt) = 0;
	virtual bool crypt_cbc(const void *dst, const void *src, size_t len, uint8_t *iv) const = 0;
};

class DH_Context : public Object {
public:
	// check that publicKey is acceptable according to §4.6.2 of RFC 7425 
	static bool checkPublicKey(const void *publicKey, size_t len);

	virtual bool init(int groupID) = 0; // must support 2, 5, 14, 16
	virtual Bytes getPublicKey() const = 0;
	virtual Bytes computeSharedSecret(const void *otherPublic, size_t len) const = 0;
};

} } } // namespace com::zenomt::rtmfp
