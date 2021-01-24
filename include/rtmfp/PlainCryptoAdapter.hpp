#pragma once

// Copyright © 2021 Michael Thornburgh
// SPDX-License-Identifier: MIT

#include "rtmfp.hpp"

namespace com { namespace zenomt { namespace rtmfp {

class PlainCryptoAdapter : public ICryptoAdapter {
public:
	PlainCryptoAdapter(const char *identity);

	std::shared_ptr<SessionCryptoKey> getKeyForNewSession() override;
	std::vector<uint8_t> getNearEncodedCertForEPD(const uint8_t *epd, size_t epdLen) override;
	bool isSelectedByEPD(const uint8_t *bytes, size_t len) override;
	std::vector<uint8_t> sign(const uint8_t *msg, size_t msgLen, std::shared_ptr<CryptoCert> recipient) override;
	bool checkNearWinsGlare(std::shared_ptr<CryptoCert> far) override;
	std::shared_ptr<CryptoCert> decodeCertificate(const uint8_t *bytes, size_t len) override;
	void pseudoRandomBytes(uint8_t *dst, size_t len) override;
	void cryptoHash256(uint8_t *dst, const uint8_t *msg, size_t len) override;

protected:
	std::vector<uint8_t> m_identity;
};

} } } // namespace com::zenomt::rtmfp
