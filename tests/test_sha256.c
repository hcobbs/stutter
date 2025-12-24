/*
 * test_sha256.c - SHA-256 test vectors
 *
 * Part of the Stutter CSPRNG library.
 * Copyright (C) 2024
 * SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * [LLM-ARCH] Generated with human review
 *
 * Test vectors from NIST FIPS 180-4 and NIST CAVS.
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

void test_sha256(void)
{
    sha256_ctx_t ctx;
    unsigned char digest[32];
    unsigned char expected[32];

    test_suite_begin("SHA-256");

    /* Test 1: Empty string */
    /* SHA256("") = e3b0c442...b855 */
    {
        const char *expected_hex =
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        hex_to_bytes(expected_hex, expected, 32);

        sha256("", 0, digest);
        TEST_ASSERT_EQ_BYTES(expected, digest, 32);
    }

    /* Test 2: "abc" */
    /* SHA256("abc") = ba7816bf...5dba */
    {
        const char *expected_hex =
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        hex_to_bytes(expected_hex, expected, 32);

        sha256("abc", 3, digest);
        TEST_ASSERT_EQ_BYTES(expected, digest, 32);
    }

    /* Test 3: 448-bit message (exactly one block minus padding) */
    /* "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" */
    {
        const char *msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        const char *expected_hex =
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1";
        hex_to_bytes(expected_hex, expected, 32);

        sha256(msg, strlen(msg), digest);
        TEST_ASSERT_EQ_BYTES(expected, digest, 32);
    }

    /* Test 4: Incremental update */
    {
        const char *expected_hex =
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        hex_to_bytes(expected_hex, expected, 32);

        sha256_init(&ctx);
        sha256_update(&ctx, "a", 1);
        sha256_update(&ctx, "b", 1);
        sha256_update(&ctx, "c", 1);
        sha256_final(&ctx, digest);
        TEST_ASSERT_EQ_BYTES(expected, digest, 32);
    }

    /* Test 5: 1 million 'a' characters (stress test) */
    {
        const char *expected_hex =
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0";
        unsigned char *big_msg;

        hex_to_bytes(expected_hex, expected, 32);

        big_msg = (unsigned char *)malloc(1000000);
        if (big_msg != NULL) {
            memset(big_msg, 'a', 1000000);
            sha256(big_msg, 1000000, digest);
            TEST_ASSERT_EQ_BYTES(expected, digest, 32);
            free(big_msg);
        }
    }

    /* Test 6: Incremental with varying chunk sizes */
    {
        const char *msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        const char *expected_hex =
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1";
        hex_to_bytes(expected_hex, expected, 32);

        sha256_init(&ctx);
        sha256_update(&ctx, msg, 10);
        sha256_update(&ctx, msg + 10, 20);
        sha256_update(&ctx, msg + 30, strlen(msg) - 30);
        sha256_final(&ctx, digest);
        TEST_ASSERT_EQ_BYTES(expected, digest, 32);
    }

    test_suite_end();
}
