/*
 * sha256.c - SHA-256 implementation using OpenSSL EVP API
 *
 * Part of the Stutter CSPRNG library.
 * Copyright (C) 2024
 * SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * [LLM-ARCH] OpenSSL migration per red team recommendation
 *
 * This module wraps OpenSSL's EVP_MD API to provide SHA-256 hashing.
 * The implementation delegates all cryptographic operations to OpenSSL,
 * which has been extensively audited and is FIPS-validated.
 */

#include "stutter_internal.h"
#include <string.h>
#include <openssl/evp.h>

void sha256_init(sha256_ctx_t *ctx)
{
    ctx->ctx = EVP_MD_CTX_new();
    if (ctx->ctx != NULL) {
        EVP_DigestInit_ex(ctx->ctx, EVP_sha256(), NULL);
    }
}

void sha256_update(sha256_ctx_t *ctx, const void *data, size_t len)
{
    if (ctx->ctx != NULL && len > 0) {
        EVP_DigestUpdate(ctx->ctx, data, len);
    }
}

void sha256_final(sha256_ctx_t *ctx, unsigned char digest[32])
{
    unsigned int len;

    if (ctx->ctx != NULL) {
        EVP_DigestFinal_ex(ctx->ctx, digest, &len);
        EVP_MD_CTX_free(ctx->ctx);
        ctx->ctx = NULL;
    } else {
        memset(digest, 0, 32);
    }
}

void sha256(const void *data, size_t len, unsigned char digest[32])
{
    sha256_ctx_t ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, digest);
}
