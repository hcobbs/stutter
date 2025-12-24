/*
 * generator.c - AES-256-CTR random number generator
 *
 * Part of the Stutter CSPRNG library.
 * Copyright (C) 2024
 * SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * [LLM-ARCH] Generated with human review
 *
 * Implements the Fortuna generator using AES-256 in counter mode.
 * After each generation, the key is rotated using generated output
 * to provide backtrack resistance.
 *
 * SECURITY:
 * - Forward secrecy: reseed mixes old_key || seed via SHA-256
 * - Backtrack resistance: key is rotated after every read operation
 * - Counter never resets: ensures (key, counter) pair is never reused
 */

#include "stutter_internal.h"
#include <string.h>

/* Increment 128-bit counter (big-endian) */
static void increment_counter(unsigned char counter[16])
{
    int i;
    for (i = 15; i >= 0; i--) {
        counter[i]++;
        if (counter[i] != 0) {
            break;
        }
    }
}

void generator_init(stutter_generator_t *gen)
{
    memset(gen, 0, sizeof(*gen));
    gen->seeded = 0;
    gen->bytes_remaining = 0;
}

void generator_reseed(stutter_generator_t *gen, const unsigned char seed[32])
{
    unsigned char new_key[32];
    sha256_ctx_t ctx;

    if (gen->seeded) {
        /*
         * Mix new seed with existing key material.
         * new_key = SHA256(old_key || seed)
         * This ensures forward secrecy: knowing seed alone is insufficient.
         */
        sha256_init(&ctx);
        sha256_update(&ctx, gen->key, 32);
        sha256_update(&ctx, seed, 32);
        sha256_final(&ctx, new_key);
    } else {
        /* First seeding: use seed directly */
        memcpy(new_key, seed, 32);
    }

    /* Store new key for future reseed mixing */
    memcpy(gen->key, new_key, 32);

    /* Initialize AES with new key */
    aes256_init(&gen->aes, new_key);

    /*
     * SECURITY: Do NOT reset counter here.
     * The counter is a monotonically increasing value that ensures
     * a (key, counter) pair is never reused even if the same seed
     * is accidentally provided twice. Counter overflow after 2^128
     * blocks is astronomically unlikely.
     *
     * Only initialize counter on first seed when it's guaranteed zero.
     */
    if (!gen->seeded) {
        memset(gen->counter, 0, sizeof(gen->counter));
    }

    /* Reset quota */
    gen->bytes_remaining = STUTTER_GENERATOR_QUOTA;

    /* Mark as seeded */
    gen->seeded = 1;

    /* Zero sensitive intermediate values */
    platform_secure_zero(new_key, sizeof(new_key));
    platform_secure_zero(&ctx, sizeof(ctx));

    STUTTER_LOG("Generator reseeded, quota reset to %zu bytes",
                gen->bytes_remaining);
}

int generator_read(stutter_generator_t *gen, void *buf, size_t len)
{
    unsigned char *out = (unsigned char *)buf;
    unsigned char block[16];
    unsigned char new_key[32];
    size_t to_copy;

    if (!gen->seeded) {
        return STUTTER_ERR_NOT_INIT;
    }

    if (len > STUTTER_MAX_REQUEST) {
        return STUTTER_ERR_INVALID;
    }

    /* Check if we need a reseed (quota exhausted) */
    if (gen->bytes_remaining == 0) {
        return STUTTER_ERR_NO_ENTROPY;
    }

    /* Generate requested bytes */
    while (len > 0) {
        /* Generate one block */
        aes256_encrypt(&gen->aes, gen->counter, block);
        increment_counter(gen->counter);

        /* Copy to output */
        if (len >= 16) {
            to_copy = 16;
        } else {
            to_copy = len;
        }
        memcpy(out, block, to_copy);
        out += to_copy;
        len -= to_copy;

        /* Update quota */
        if (gen->bytes_remaining >= to_copy) {
            gen->bytes_remaining -= to_copy;
        } else {
            gen->bytes_remaining = 0;
        }
    }

    /*
     * Backtrack resistance: generate 2 extra blocks for new key.
     * Even if attacker captures state after this point, they cannot
     * recover the output we just generated.
     */
    aes256_encrypt(&gen->aes, gen->counter, new_key);
    increment_counter(gen->counter);
    aes256_encrypt(&gen->aes, gen->counter, new_key + 16);
    increment_counter(gen->counter);

    /* Update stored key for future reseed mixing */
    memcpy(gen->key, new_key, 32);

    /* Re-initialize AES with new key */
    aes256_done(&gen->aes);
    aes256_init(&gen->aes, new_key);

    /*
     * SECURITY: Do NOT reset counter here.
     * Counter continues incrementing to ensure (key, counter) uniqueness.
     */

    /* Zero sensitive values */
    platform_secure_zero(block, sizeof(block));
    platform_secure_zero(new_key, sizeof(new_key));

    return STUTTER_OK;
}

void generator_shutdown(stutter_generator_t *gen)
{
    aes256_done(&gen->aes);
    platform_secure_zero(gen->key, sizeof(gen->key));
    platform_secure_zero(gen->counter, sizeof(gen->counter));
    gen->seeded = 0;
    gen->bytes_remaining = 0;

    STUTTER_LOG("Generator shutdown complete");
}
