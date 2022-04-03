// Copyright © 2022 Michael Thornburgh
// SPDX-License-Identifier: MIT

// This module provides a concrete SimpleWebSocket using OpenSSL for SHA-1.
// Note: *not* WSS (TLS). That's a job for an IStreamPlatformAdapter.

#include <openssl/evp.h>

#include "SimpleWebSocket.hpp"

namespace com { namespace zenomt { namespace websock {

void SimpleWebSocket_OpenSSL::sha1(void *dst, const void *msg, size_t len)
{
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex(ctx, EVP_sha1(), NULL);
	EVP_DigestUpdate(ctx, msg, len);
	EVP_DigestFinal_ex(ctx, (unsigned char *)dst, NULL);
	EVP_MD_CTX_free(ctx);
}

} } } // namespace com::zenomt::websock
