/*
 * aes256.c - AES-256 implementation using OpenSSL EVP API
 *
 * Part of the Stutter CSPRNG library.
 * Copyright (C) 2024
 * SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * [LLM-ARCH] OpenSSL migration per red team recommendation
 *
 * This module wraps OpenSSL's EVP_CIPHER API to provide AES-256 encryption.
 * The implementation delegates all cryptographic operations to OpenSSL,
 * which has been extensively audited and is FIPS-validated.
 *
 * Note: This uses AES-256-ECB for single-block encryption. The caller
 * (generator.c) implements CTR mode on top of this primitive.
 */

#include "stutter_internal.h"
#include <string.h>
#include <openssl/evp.h>

void aes256_init(aes256_ctx_t *ctx, const unsigned char key[32])
{
    ctx->ctx = EVP_CIPHER_CTX_new();
    if (ctx->ctx != NULL) {
        /*
         * Initialize for AES-256-ECB encryption.
         * ECB mode is used because we encrypt single blocks; the caller
         * implements CTR mode by managing the counter externally.
         * Padding is disabled since we always encrypt exactly 16 bytes.
         */
        EVP_EncryptInit_ex(ctx->ctx, EVP_aes_256_ecb(), NULL, key, NULL);
        EVP_CIPHER_CTX_set_padding(ctx->ctx, 0);
    }
}

void aes256_encrypt(const aes256_ctx_t *ctx,
                    const unsigned char in[16],
                    unsigned char out[16])
{
    int outlen;

    if (ctx->ctx != NULL) {
        EVP_EncryptUpdate(ctx->ctx, out, &outlen, in, 16);
    } else {
        memset(out, 0, 16);
    }
}

void aes256_done(aes256_ctx_t *ctx)
{
    if (ctx->ctx != NULL) {
        EVP_CIPHER_CTX_free(ctx->ctx);
        ctx->ctx = NULL;
    }
}
