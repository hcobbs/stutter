/*
 * test_aes256.c - AES-256 test vectors
 *
 * Part of the Stutter CSPRNG library.
 * Copyright (C) 2024
 * SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * [LLM-ARCH] Generated with human review
 *
 * Test vectors from NIST FIPS 197.
 */

#include "test_harness.h"
#include "stutter_internal.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* Helper to convert hex string to bytes */
static void hex_to_bytes(const char *hex, unsigned char *out, size_t len)
{
    size_t i;
    for (i = 0; i < len; i++) {
        unsigned int byte;
        sscanf(hex + 2 * i, "%2x", &byte);
        out[i] = (unsigned char)byte;
    }
}

void test_aes256(void)
{
    aes256_ctx_t ctx;
    unsigned char key[32];
    unsigned char plaintext[16];
    unsigned char ciphertext[16];
    unsigned char expected[16];

    test_suite_begin("AES-256");

    /* FIPS 197 Appendix C.3: AES-256 test vector */
    {
        const char *key_hex =
            "000102030405060708090a0b0c0d0e0f"
            "101112131415161718191a1b1c1d1e1f";
        const char *pt_hex = "00112233445566778899aabbccddeeff";
        const char *ct_hex = "8ea2b7ca516745bfeafc49904b496089";

        hex_to_bytes(key_hex, key, 32);
        hex_to_bytes(pt_hex, plaintext, 16);
        hex_to_bytes(ct_hex, expected, 16);

        aes256_init(&ctx, key);
        aes256_encrypt(&ctx, plaintext, ciphertext);
        aes256_done(&ctx);

        TEST_ASSERT_EQ_BYTES(expected, ciphertext, 16);
    }

    /* Test with all-zero key and plaintext */
    {
        const char *key_hex =
            "0000000000000000000000000000000000000000000000000000000000000000";
        const char *pt_hex = "00000000000000000000000000000000";
        const char *ct_hex = "dc95c078a2408989ad48a21492842087";

        hex_to_bytes(key_hex, key, 32);
        hex_to_bytes(pt_hex, plaintext, 16);
        hex_to_bytes(ct_hex, expected, 16);

        aes256_init(&ctx, key);
        aes256_encrypt(&ctx, plaintext, ciphertext);
        aes256_done(&ctx);

        TEST_ASSERT_EQ_BYTES(expected, ciphertext, 16);
    }

    /* Test multiple encryptions with same key */
    {
        const char *key_hex =
            "000102030405060708090a0b0c0d0e0f"
            "101112131415161718191a1b1c1d1e1f";
        const char *pt_hex = "00112233445566778899aabbccddeeff";
        const char *ct_hex = "8ea2b7ca516745bfeafc49904b496089";
        unsigned char ciphertext2[16];

        hex_to_bytes(key_hex, key, 32);
        hex_to_bytes(pt_hex, plaintext, 16);
        hex_to_bytes(ct_hex, expected, 16);

        aes256_init(&ctx, key);

        /* First encryption */
        aes256_encrypt(&ctx, plaintext, ciphertext);
        TEST_ASSERT_EQ_BYTES(expected, ciphertext, 16);

        /* Second encryption (should produce same result) */
        aes256_encrypt(&ctx, plaintext, ciphertext2);
        TEST_ASSERT_EQ_BYTES(expected, ciphertext2, 16);

        aes256_done(&ctx);
    }

    /* Test that aes256_done cleans up the context */
    {
        const char *key_hex =
            "000102030405060708090a0b0c0d0e0f"
            "101112131415161718191a1b1c1d1e1f";

        hex_to_bytes(key_hex, key, 32);

        aes256_init(&ctx, key);
        aes256_done(&ctx);

        /* Check that context pointer is NULL after cleanup */
        TEST_ASSERT(ctx.ctx == NULL);
    }

    test_suite_end();
}
