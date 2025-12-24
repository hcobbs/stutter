/*
 * accumulator.c - Fortuna 32-pool entropy accumulator
 *
 * Part of the Stutter CSPRNG library.
 * Copyright (C) 2024
 * SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * [LLM-ARCH] Generated with human review
 *
 * Implements the Fortuna accumulator as described by Ferguson & Schneier.
 * Pool i is included in reseed when (reseed_count % 2^i) == 0.
 * This provides recovery guarantees even if attacker knows some pool states.
 */

#include "stutter_internal.h"
#include <string.h>
#include <limits.h>

void accumulator_init(stutter_accumulator_t *acc)
{
    int i;

    for (i = 0; i < STUTTER_NUM_POOLS; i++) {
        /* Ignore return value in init; failure will be caught on first use */
        sha256_init(&acc->pools[i].hash_ctx);
        acc->pools[i].entropy_bits = 0;
        stutter_spin_init(&acc->pools[i].lock);
    }

    acc->reseed_count = 0;
    pthread_mutex_init(&acc->reseed_mutex, NULL);

    STUTTER_LOG("Accumulator initialized with %d pools", STUTTER_NUM_POOLS);
}

void accumulator_add(stutter_accumulator_t *acc, unsigned int pool,
                     const void *data, size_t len, unsigned int quality)
{
    size_t entropy_estimate;
    size_t max_entropy;

    if (pool >= STUTTER_NUM_POOLS || data == NULL || len == 0) {
        return;
    }

    /* Clamp quality to valid range */
    if (quality > 8) {
        quality = 8;
    }

    /*
     * Estimate entropy: quality bits per byte, capped at actual bits.
     * Check for overflow before multiplication.
     */
    if (len > SIZE_MAX / quality) {
        entropy_estimate = SIZE_MAX;  /* Saturate on overflow */
    } else {
        entropy_estimate = len * quality;
    }

    /* Cap at actual data bits (len * 8) */
    if (len <= SIZE_MAX / 8) {
        max_entropy = len * 8;
        if (entropy_estimate > max_entropy) {
            entropy_estimate = max_entropy;
        }
    }

    /* Lock this pool only */
    stutter_spin_lock(&acc->pools[pool].lock);

    /* Add data to pool's running hash (ignore errors; best effort) */
    sha256_update(&acc->pools[pool].hash_ctx, data, len);

    /* Update entropy estimate (cap at reasonable maximum) */
    acc->pools[pool].entropy_bits += entropy_estimate;
    if (acc->pools[pool].entropy_bits > 4096) {
        acc->pools[pool].entropy_bits = 4096;
    }

    stutter_spin_unlock(&acc->pools[pool].lock);

    STUTTER_LOG("Added %zu bytes to pool %u (est. %zu bits, quality %u)",
                len, pool, entropy_estimate, quality);
}

int accumulator_get_entropy_estimate(stutter_accumulator_t *acc,
                                      unsigned int pool)
{
    size_t bits;
    int result;

    if (pool >= STUTTER_NUM_POOLS) {
        return 0;
    }

    stutter_spin_lock(&acc->pools[pool].lock);
    bits = acc->pools[pool].entropy_bits;
    stutter_spin_unlock(&acc->pools[pool].lock);

    /* Prevent truncation: clamp to INT_MAX */
    if (bits > (size_t)INT_MAX) {
        result = INT_MAX;
    } else {
        result = (int)bits;
    }

    return result;
}

int accumulator_reseed(stutter_accumulator_t *acc, unsigned char seed[32])
{
    sha256_ctx_t seed_hash;
    unsigned char pool_digest[32];
    unsigned long mask;
    int i;
    int pools_used;
    int result;

    /* Acquire reseed mutex (only one thread can reseed at a time) */
    pthread_mutex_lock(&acc->reseed_mutex);

    /* Check if pool 0 has enough entropy */
    stutter_spin_lock(&acc->pools[0].lock);
    if (acc->pools[0].entropy_bits < STUTTER_POOL_THRESHOLD) {
        stutter_spin_unlock(&acc->pools[0].lock);
        pthread_mutex_unlock(&acc->reseed_mutex);
        STUTTER_LOG("Reseed failed: pool 0 has %zu bits (need %d)",
                    acc->pools[0].entropy_bits, STUTTER_POOL_THRESHOLD);
        return STUTTER_ERR_NO_ENTROPY;
    }
    stutter_spin_unlock(&acc->pools[0].lock);

    /* Increment reseed counter (saturate at max to prevent schedule repeat) */
    if (acc->reseed_count < ULONG_MAX) {
        acc->reseed_count++;
    }

    /* Initialize seed hash */
    result = sha256_init(&seed_hash);
    if (result != STUTTER_OK) {
        pthread_mutex_unlock(&acc->reseed_mutex);
        return result;
    }

    /* Collect from eligible pools based on Fortuna schedule */
    pools_used = 0;
    for (i = 0; i < STUTTER_NUM_POOLS; i++) {
        /* Pool i is used when (reseed_count % 2^i) == 0 */
        mask = (1UL << i);

        if ((acc->reseed_count & (mask - 1)) == 0) {
            stutter_spin_lock(&acc->pools[i].lock);

            /* Finalize this pool's hash and add to seed material */
            result = sha256_final(&acc->pools[i].hash_ctx, pool_digest);
            if (result != STUTTER_OK) {
                stutter_spin_unlock(&acc->pools[i].lock);
                platform_secure_zero(pool_digest, sizeof(pool_digest));
                pthread_mutex_unlock(&acc->reseed_mutex);
                return result;
            }

            /* Add pool digest to seed hash */
            result = sha256_update(&seed_hash, pool_digest, 32);
            if (result != STUTTER_OK) {
                stutter_spin_unlock(&acc->pools[i].lock);
                platform_secure_zero(pool_digest, sizeof(pool_digest));
                pthread_mutex_unlock(&acc->reseed_mutex);
                return result;
            }

            /* Re-initialize pool for next accumulation cycle */
            sha256_init(&acc->pools[i].hash_ctx);
            acc->pools[i].entropy_bits = 0;

            stutter_spin_unlock(&acc->pools[i].lock);
            pools_used++;
        }
    }

    /* Finalize seed */
    result = sha256_final(&seed_hash, seed);
    if (result != STUTTER_OK) {
        platform_secure_zero(pool_digest, sizeof(pool_digest));
        pthread_mutex_unlock(&acc->reseed_mutex);
        return result;
    }

    /* Zero intermediate values */
    platform_secure_zero(pool_digest, sizeof(pool_digest));
    platform_secure_zero(&seed_hash, sizeof(seed_hash));

    pthread_mutex_unlock(&acc->reseed_mutex);

    STUTTER_LOG("Reseed #%lu complete using %d pools",
                acc->reseed_count, pools_used);

    return STUTTER_OK;
}

void accumulator_shutdown(stutter_accumulator_t *acc)
{
    int i;

    /* Zero all pool states */
    for (i = 0; i < STUTTER_NUM_POOLS; i++) {
        stutter_spin_lock(&acc->pools[i].lock);
        platform_secure_zero(&acc->pools[i].hash_ctx,
                             sizeof(acc->pools[i].hash_ctx));
        acc->pools[i].entropy_bits = 0;
        stutter_spin_unlock(&acc->pools[i].lock);
        stutter_spin_destroy(&acc->pools[i].lock);
    }

    pthread_mutex_destroy(&acc->reseed_mutex);
    acc->reseed_count = 0;

    STUTTER_LOG("Accumulator shutdown complete");
}
