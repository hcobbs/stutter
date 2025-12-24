/*
 * test_accumulator.c - Accumulator tests
 *
 * Part of the Stutter CSPRNG library.
 * Copyright (C) 2024
 * SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * [LLM-ARCH] Generated with human review
 *
 * Tests the 32-pool Fortuna accumulator.
 */

#include "test_harness.h"
#include "stutter_internal.h"
#include <string.h>

void test_accumulator(void)
{
    stutter_accumulator_t acc;
    unsigned char seed[32];
    unsigned char entropy[64];
    int result;
    int i;

    test_suite_begin("Accumulator");

    /* Test 1: Basic initialization */
    {
        accumulator_init(&acc);

        /* All pools should start with zero entropy */
        for (i = 0; i < STUTTER_NUM_POOLS; i++) {
            TEST_ASSERT_EQ(accumulator_get_entropy_estimate(&acc, i), 0);
        }

        accumulator_shutdown(&acc);
    }

    /* Test 2: Adding entropy increases estimate */
    {
        accumulator_init(&acc);

        memset(entropy, 0x42, sizeof(entropy));
        accumulator_add(&acc, 0, entropy, 32, 8); /* 32 bytes, 8 bits/byte */

        TEST_ASSERT(accumulator_get_entropy_estimate(&acc, 0) >= 256);

        accumulator_shutdown(&acc);
    }

    /* Test 3: Reseed fails without enough entropy */
    {
        accumulator_init(&acc);

        /* No entropy added */
        result = accumulator_reseed(&acc, seed);
        TEST_ASSERT_EQ(result, STUTTER_ERR_NO_ENTROPY);

        accumulator_shutdown(&acc);
    }

    /* Test 4: Reseed succeeds with enough entropy */
    {
        accumulator_init(&acc);

        /* Add enough entropy to pool 0 */
        memset(entropy, 0x42, sizeof(entropy));
        accumulator_add(&acc, 0, entropy, 32, 8); /* 256 bits */

        result = accumulator_reseed(&acc, seed);
        TEST_ASSERT_EQ(result, STUTTER_OK);

        /* Seed should not be all zeros */
        {
            int all_zero = 1;
            for (i = 0; i < 32; i++) {
                if (seed[i] != 0) {
                    all_zero = 0;
                    break;
                }
            }
            TEST_ASSERT(!all_zero);
        }

        accumulator_shutdown(&acc);
    }

    /* Test 5: Reseed clears pool 0 entropy */
    {
        accumulator_init(&acc);

        memset(entropy, 0x42, sizeof(entropy));
        accumulator_add(&acc, 0, entropy, 32, 8);

        result = accumulator_reseed(&acc, seed);
        TEST_ASSERT_EQ(result, STUTTER_OK);

        /* Pool 0 should now have zero entropy */
        TEST_ASSERT_EQ(accumulator_get_entropy_estimate(&acc, 0), 0);

        accumulator_shutdown(&acc);
    }

    /* Test 6: Pool scheduling (Fortuna schedule) */
    {
        unsigned long reseed_count;

        accumulator_init(&acc);

        /*
         * Fortuna pool schedule:
         * - Pool 0 used every reseed
         * - Pool 1 used every 2nd reseed
         * - Pool 2 used every 4th reseed
         * - Pool i used every 2^i reseed
         */

        /* Add entropy to pools 0, 1, 2 */
        for (i = 0; i < 3; i++) {
            memset(entropy, 0x42 + i, sizeof(entropy));
            accumulator_add(&acc, i, entropy, 32, 8);
        }

        /* First reseed: only pool 0 used */
        result = accumulator_reseed(&acc, seed);
        TEST_ASSERT_EQ(result, STUTTER_OK);
        reseed_count = acc.reseed_count;
        TEST_ASSERT_EQ(reseed_count, 1UL);

        /* Pool 0 should be empty, pools 1,2 should still have entropy */
        TEST_ASSERT_EQ(accumulator_get_entropy_estimate(&acc, 0), 0);
        TEST_ASSERT(accumulator_get_entropy_estimate(&acc, 1) > 0);
        TEST_ASSERT(accumulator_get_entropy_estimate(&acc, 2) > 0);

        /* Add more to pool 0 for next reseed */
        accumulator_add(&acc, 0, entropy, 32, 8);

        /* Second reseed: pools 0 and 1 used */
        result = accumulator_reseed(&acc, seed);
        TEST_ASSERT_EQ(result, STUTTER_OK);

        TEST_ASSERT_EQ(accumulator_get_entropy_estimate(&acc, 0), 0);
        TEST_ASSERT_EQ(accumulator_get_entropy_estimate(&acc, 1), 0);
        TEST_ASSERT(accumulator_get_entropy_estimate(&acc, 2) > 0);

        accumulator_shutdown(&acc);
    }

    /* Test 7: Different entropy produces different seeds */
    {
        unsigned char seed2[32];

        accumulator_init(&acc);
        memset(entropy, 0x42, sizeof(entropy));
        accumulator_add(&acc, 0, entropy, 32, 8);
        accumulator_reseed(&acc, seed);
        accumulator_shutdown(&acc);

        accumulator_init(&acc);
        memset(entropy, 0x43, sizeof(entropy));
        accumulator_add(&acc, 0, entropy, 32, 8);
        accumulator_reseed(&acc, seed2);
        accumulator_shutdown(&acc);

        TEST_ASSERT(memcmp(seed, seed2, 32) != 0);
    }

    /* Test 8: Quality parameter affects entropy estimate */
    {
        accumulator_init(&acc);

        /* Add 32 bytes with quality 1 (1 bit/byte) */
        memset(entropy, 0x42, sizeof(entropy));
        accumulator_add(&acc, 0, entropy, 32, 1);

        /* Should have ~32 bits, not 256 */
        TEST_ASSERT(accumulator_get_entropy_estimate(&acc, 0) <= 64);
        TEST_ASSERT(accumulator_get_entropy_estimate(&acc, 0) >= 16);

        accumulator_shutdown(&acc);
    }

    /* Test 9: Invalid pool number is ignored */
    {
        accumulator_init(&acc);

        /* Try to add to invalid pool */
        memset(entropy, 0x42, sizeof(entropy));
        accumulator_add(&acc, 99, entropy, 32, 8);

        /* Should not crash, and valid pools should be unaffected */
        TEST_ASSERT_EQ(accumulator_get_entropy_estimate(&acc, 0), 0);

        accumulator_shutdown(&acc);
    }

    test_suite_end();
}
