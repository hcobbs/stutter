/*
 * test_thread.c - Threading tests
 *
 * Part of the Stutter CSPRNG library.
 * Copyright (C) 2024
 * SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * [LLM-ARCH] Generated with human review
 *
 * Tests thread safety of the full library.
 */

#include "test_harness.h"
#include "../include/stutter.h"
#include <pthread.h>
#include <string.h>
#include <stdlib.h>

#define NUM_THREADS 4
#define ITERATIONS 100
#define BYTES_PER_ITER 64

typedef struct {
    int thread_id;
    int success;
    unsigned char samples[ITERATIONS][BYTES_PER_ITER];
} thread_data_t;

static void *thread_func(void *arg)
{
    thread_data_t *data = (thread_data_t *)arg;
    int i;
    int result;

    data->success = 1;

    for (i = 0; i < ITERATIONS; i++) {
        result = stutter_rand(data->samples[i], BYTES_PER_ITER);
        if (result != STUTTER_OK) {
            data->success = 0;
            break;
        }
    }

    return NULL;
}

void test_thread(void)
{
    pthread_t threads[NUM_THREADS];
    thread_data_t thread_data[NUM_THREADS];
    int i, j, k;
    int result;
    int all_success;
    int duplicates_found;

    test_suite_begin("Threading");

    /* Initialize library */
    result = stutter_init();
    TEST_ASSERT_EQ(result, STUTTER_OK);

    if (result != STUTTER_OK) {
        test_suite_end();
        return;
    }

    /* Test 1: Concurrent generation from multiple threads */
    {
        /* Initialize thread data */
        for (i = 0; i < NUM_THREADS; i++) {
            thread_data[i].thread_id = i;
            thread_data[i].success = 0;
            memset(thread_data[i].samples, 0, sizeof(thread_data[i].samples));
        }

        /* Launch threads */
        for (i = 0; i < NUM_THREADS; i++) {
            pthread_create(&threads[i], NULL, thread_func, &thread_data[i]);
        }

        /* Wait for completion */
        for (i = 0; i < NUM_THREADS; i++) {
            pthread_join(threads[i], NULL);
        }

        /* Check all threads succeeded */
        all_success = 1;
        for (i = 0; i < NUM_THREADS; i++) {
            if (!thread_data[i].success) {
                all_success = 0;
                break;
            }
        }
        TEST_ASSERT(all_success);
    }

    /* Test 2: No duplicate outputs within a thread */
    {
        duplicates_found = 0;

        for (i = 0; i < NUM_THREADS && !duplicates_found; i++) {
            for (j = 0; j < ITERATIONS && !duplicates_found; j++) {
                for (k = j + 1; k < ITERATIONS && !duplicates_found; k++) {
                    if (memcmp(thread_data[i].samples[j],
                               thread_data[i].samples[k],
                               BYTES_PER_ITER) == 0) {
                        duplicates_found = 1;
                    }
                }
            }
        }

        TEST_ASSERT(!duplicates_found);
    }

    /* Test 3: No duplicate outputs across threads */
    {
        duplicates_found = 0;

        for (i = 0; i < NUM_THREADS && !duplicates_found; i++) {
            for (j = i + 1; j < NUM_THREADS && !duplicates_found; j++) {
                for (k = 0; k < ITERATIONS && !duplicates_found; k++) {
                    int m;
                    for (m = 0; m < ITERATIONS && !duplicates_found; m++) {
                        if (memcmp(thread_data[i].samples[k],
                                   thread_data[j].samples[m],
                                   BYTES_PER_ITER) == 0) {
                            duplicates_found = 1;
                        }
                    }
                }
            }
        }

        TEST_ASSERT(!duplicates_found);
    }

    /* Test 4: Multiple init calls are safe */
    {
        result = stutter_init();
        TEST_ASSERT_EQ(result, STUTTER_OK);

        result = stutter_init();
        TEST_ASSERT_EQ(result, STUTTER_OK);
    }

    /* Test 5: Generation after reseed */
    {
        unsigned char buf[32];

        result = stutter_reseed();
        TEST_ASSERT_EQ(result, STUTTER_OK);

        result = stutter_rand(buf, sizeof(buf));
        TEST_ASSERT_EQ(result, STUTTER_OK);
    }

    /* Test 6: Seeded status */
    {
        TEST_ASSERT(stutter_is_seeded());
    }

    /* Test 7: Reseed count increases */
    {
        int count1;
        int count2;

        count1 = stutter_get_reseed_count();
        stutter_reseed();
        count2 = stutter_get_reseed_count();

        TEST_ASSERT(count2 > count1);
    }

    /* Cleanup */
    stutter_shutdown();

    /* Test 8: Operations fail after shutdown */
    {
        unsigned char buf[32];
        result = stutter_rand(buf, sizeof(buf));
        TEST_ASSERT_EQ(result, STUTTER_ERR_NOT_INIT);
    }

    test_suite_end();
}
