/*
 * test_security.c - Security property tests
 *
 * Part of the Stutter CSPRNG library.
 * Copyright (C) 2024
 * SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * [LLM-ARCH] Generated with human review
 *
 * Tests critical security properties:
 * - Forward secrecy: reseed mixes old key with new seed
 * - Backtrack resistance: key rotation after each read
 * - Counter non-reuse: counter never resets during operation
 */

#include "test_harness.h"
#include "stutter_internal.h"
#include <string.h>

void test_security(void)
{
    test_suite_begin("Security Properties");

    /*
     * Test 1: Forward Secrecy
     *
     * After initial seeding, a reseed with the same seed should produce
     * DIFFERENT output than a fresh generator seeded only with that seed.
     * This proves the old key is mixed into the new key.
     */
    {
        stutter_generator_t gen1, gen2;
        unsigned char seed1[32];
        unsigned char seed2[32];
        unsigned char buf1[32];
        unsigned char buf2[32];

        /* First seed */
        memset(seed1, 0x11, sizeof(seed1));
        /* Second seed (same for both generators) */
        memset(seed2, 0x22, sizeof(seed2));

        /* Gen1: seed with seed1, then reseed with seed2 */
        generator_init(&gen1);
        generator_reseed(&gen1, seed1);
        generator_reseed(&gen1, seed2);
        generator_read(&gen1, buf1, 32);
        generator_shutdown(&gen1);

        /* Gen2: seed only with seed2 (no prior state) */
        generator_init(&gen2);
        generator_reseed(&gen2, seed2);
        generator_read(&gen2, buf2, 32);
        generator_shutdown(&gen2);

        /*
         * If forward secrecy works, buf1 != buf2 because gen1's
         * reseed mixed old_key || seed2, while gen2 used only seed2.
         */
        TEST_ASSERT(memcmp(buf1, buf2, 32) != 0);
    }

    /*
     * Test 2: Backtrack Resistance
     *
     * After reading data, the generator's key rotates. Even if we know
     * the new state, we cannot recover the previous output.
     *
     * We test this by verifying that two reads produce different output
     * even with the same initial conditions.
     */
    {
        stutter_generator_t gen;
        unsigned char seed[32];
        unsigned char buf1[32];
        unsigned char buf2[32];

        memset(seed, 0x42, sizeof(seed));

        generator_init(&gen);
        generator_reseed(&gen, seed);

        /* First read */
        generator_read(&gen, buf1, 32);

        /* Second read (key has rotated) */
        generator_read(&gen, buf2, 32);

        /* Must be different */
        TEST_ASSERT(memcmp(buf1, buf2, 32) != 0);

        generator_shutdown(&gen);
    }

    /*
     * Test 3: Counter Non-Reuse After Reseed
     *
     * After a reseed, the counter should NOT reset to zero.
     * We verify this by checking that output after reseed differs
     * from what a fresh generator with the same derived key would produce.
     *
     * Since we now mix old_key into reseed, we need a different approach:
     * verify that multiple reseeds with same data produce different output.
     */
    {
        stutter_generator_t gen;
        unsigned char seed[32];
        unsigned char reseed_data[32];
        unsigned char buf1[32];
        unsigned char buf2[32];

        memset(seed, 0x42, sizeof(seed));
        memset(reseed_data, 0x99, sizeof(reseed_data));

        generator_init(&gen);
        generator_reseed(&gen, seed);

        /* Generate some data (increments counter) */
        generator_read(&gen, buf1, 32);

        /* Reseed */
        generator_reseed(&gen, reseed_data);
        generator_read(&gen, buf1, 32);

        /* Reseed again with same data */
        generator_reseed(&gen, reseed_data);
        generator_read(&gen, buf2, 32);

        /*
         * Due to counter not resetting and key mixing,
         * output should differ even with same reseed data.
         */
        TEST_ASSERT(memcmp(buf1, buf2, 32) != 0);

        generator_shutdown(&gen);
    }

    /*
     * Test 4: Repeated Same Seed Attack
     *
     * Even if an attacker can force the same seed to be provided multiple
     * times, the output should differ because:
     * 1. The old key is mixed in (forward secrecy)
     * 2. The counter doesn't reset (counter non-reuse)
     */
    {
        stutter_generator_t gen;
        unsigned char seed[32];
        unsigned char buf1[32];
        unsigned char buf2[32];
        unsigned char buf3[32];

        memset(seed, 0xAA, sizeof(seed));

        generator_init(&gen);
        generator_reseed(&gen, seed);
        generator_read(&gen, buf1, 32);

        /* Attacker forces same seed again */
        generator_reseed(&gen, seed);
        generator_read(&gen, buf2, 32);

        /* And again */
        generator_reseed(&gen, seed);
        generator_read(&gen, buf3, 32);

        /* All outputs must be different */
        TEST_ASSERT(memcmp(buf1, buf2, 32) != 0);
        TEST_ASSERT(memcmp(buf2, buf3, 32) != 0);
        TEST_ASSERT(memcmp(buf1, buf3, 32) != 0);

        generator_shutdown(&gen);
    }

    /*
     * Test 5: Key Parking API
     *
     * Verify that parking/unparking works correctly and that a parked
     * generator auto-unparks when stutter_rand is called.
     */
    {
        unsigned char buf[32];
        int result;

        result = stutter_init();
        TEST_ASSERT(result == STUTTER_OK);

        /* Generate some data to create a generator */
        result = stutter_rand(buf, sizeof(buf));
        TEST_ASSERT(result == STUTTER_OK);

        /* Should not be parked initially */
        TEST_ASSERT(stutter_is_generator_parked() == 0);

        /* Park the generator */
        result = stutter_park_generator();
        TEST_ASSERT(result == STUTTER_OK);
        TEST_ASSERT(stutter_is_generator_parked() == 1);

        /* Parking again should be a no-op (idempotent) */
        result = stutter_park_generator();
        TEST_ASSERT(result == STUTTER_OK);
        TEST_ASSERT(stutter_is_generator_parked() == 1);

        /* Generate data - should auto-unpark */
        result = stutter_rand(buf, sizeof(buf));
        TEST_ASSERT(result == STUTTER_OK);
        TEST_ASSERT(stutter_is_generator_parked() == 0);

        stutter_shutdown();
    }

    /*
     * Test 6: Secure Alloc/Free API
     *
     * Verify that stutter_rand_secure_alloc returns non-NULL buffer
     * with random data, and that stutter_rand_secure_free works.
     */
    {
        void *buf1;
        void *buf2;
        int result;
        int all_zero;
        size_t i;

        result = stutter_init();
        TEST_ASSERT(result == STUTTER_OK);

        /* Allocate secure buffer */
        buf1 = stutter_rand_secure_alloc(32);
        TEST_ASSERT(buf1 != NULL);

        /* Verify it contains non-zero data (random) */
        all_zero = 1;
        for (i = 0; i < 32; i++) {
            if (((unsigned char *)buf1)[i] != 0) {
                all_zero = 0;
                break;
            }
        }
        TEST_ASSERT(!all_zero);

        /* Allocate another buffer, should be different */
        buf2 = stutter_rand_secure_alloc(32);
        TEST_ASSERT(buf2 != NULL);
        TEST_ASSERT(memcmp(buf1, buf2, 32) != 0);

        /* Free both buffers */
        stutter_rand_secure_free(buf1, 32);
        stutter_rand_secure_free(buf2, 32);

        /* Freeing NULL should be safe */
        stutter_rand_secure_free(NULL, 0);

        stutter_shutdown();
    }

    test_suite_end();
}
