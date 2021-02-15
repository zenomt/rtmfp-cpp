#pragma once

// Copyright © 2021 Michael Thornburgh
// SPDX-License-Identifier: MIT

// This module provides a concrete implementation of a FlashCryptoAdapter
// using OpenSSL.

#include "FlashCryptoAdapter.hpp"

namespace com { namespace zenomt { namespace rtmfp {

class FlashCryptoAdapter_OpenSSL : public FlashCryptoAdapter {
public:
	void pseudoRandomBytes(uint8_t *dst, size_t len) override;
	std::vector<int> getSupportedDHGroups() const override;
	void sha256(void *dst, const void *msg, size_t len) const override;

	std::shared_ptr<HMACSHA256_Context> makeHMAC_Context() override;
	std::shared_ptr<AES_Context> makeAES_Context() override;
	std::shared_ptr<DH_Context> makeDH_Context() override;
};

} } } // namespace com::zenomt::rtmfp
