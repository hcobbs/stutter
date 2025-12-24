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

int sha256_init(sha256_ctx_t *ctx)
{
    ctx->ctx = EVP_MD_CTX_new();
    if (ctx->ctx == NULL) {
        return STUTTER_ERR_PLATFORM;
    }

    if (EVP_DigestInit_ex(ctx->ctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(ctx->ctx);
        ctx->ctx = NULL;
        return STUTTER_ERR_PLATFORM;
    }

    return STUTTER_OK;
}

int sha256_update(sha256_ctx_t *ctx, const void *data, size_t len)
{
    if (ctx->ctx == NULL) {
        return STUTTER_ERR_PLATFORM;
    }

    if (len == 0) {
        return STUTTER_OK;
    }

    if (EVP_DigestUpdate(ctx->ctx, data, len) != 1) {
        return STUTTER_ERR_PLATFORM;
    }

    return STUTTER_OK;
}

int sha256_final(sha256_ctx_t *ctx, unsigned char digest[32])
{
    unsigned int len;
    int result;

    if (ctx->ctx == NULL) {
        memset(digest, 0, 32);
        return STUTTER_ERR_PLATFORM;
    }

    result = EVP_DigestFinal_ex(ctx->ctx, digest, &len);
    EVP_MD_CTX_free(ctx->ctx);
    ctx->ctx = NULL;

    if (result != 1) {
        memset(digest, 0, 32);
        return STUTTER_ERR_PLATFORM;
    }

    return STUTTER_OK;
}

int sha256(const void *data, size_t len, unsigned char digest[32])
{
    sha256_ctx_t ctx;
    int result;

    result = sha256_init(&ctx);
    if (result != STUTTER_OK) {
        memset(digest, 0, 32);
        return result;
    }

    result = sha256_update(&ctx, data, len);
    if (result != STUTTER_OK) {
        if (ctx.ctx != NULL) {
            EVP_MD_CTX_free(ctx.ctx);
        }
        memset(digest, 0, 32);
        return result;
    }

    return sha256_final(&ctx, digest);
}
