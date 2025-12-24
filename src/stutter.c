/*
 * stutter.c - Main library implementation
 *
 * Part of the Stutter CSPRNG library.
 * Copyright (C) 2024
 * SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * [LLM-ARCH] Generated with human review
 *
 * Coordinates the accumulator, generator, and entropy subsystems.
 * Provides the public API with thread-local generators.
 */

#include "stutter_internal.h"
#include <stdlib.h>

/* ============================================================================
 * Global State
 * ============================================================================ */

static stutter_accumulator_t g_accumulator;
static pthread_key_t g_generator_key;
static pthread_once_t g_tls_init_once = PTHREAD_ONCE_INIT;
static pthread_mutex_t g_init_mutex = PTHREAD_MUTEX_INITIALIZER;
static int g_initialized = 0;

/* ============================================================================
 * Thread-Local Generator Management
 * ============================================================================ */

static void generator_destructor(void *ptr)
{
    stutter_generator_t *gen = (stutter_generator_t *)ptr;
    if (gen != NULL) {
        generator_shutdown(gen);
        platform_secure_zero(gen, sizeof(*gen));
        free(gen);
    }
}

static void tls_init(void)
{
    pthread_key_create(&g_generator_key, generator_destructor);
}

static stutter_generator_t *get_thread_generator(void)
{
    stutter_generator_t *gen;
    unsigned char seed[32];
    int result;
    int attempts;

    gen = (stutter_generator_t *)pthread_getspecific(g_generator_key);
    if (gen != NULL) {
        return gen;
    }

    /* Create new generator for this thread */
    gen = (stutter_generator_t *)malloc(sizeof(*gen));
    if (gen == NULL) {
        return NULL;
    }

    generator_init(gen);

    /*
     * Perform initial reseed. We need pool 0 to have enough entropy.
     * Gather entropy directly into pool 0 to ensure it gets sufficient bits.
     */
    result = STUTTER_ERR_NO_ENTROPY;
    for (attempts = 0; attempts < 10 && result == STUTTER_ERR_NO_ENTROPY; attempts++) {
        unsigned char entropy_buf[64];

        /* Gather entropy directly from system and add to pool 0 */
        if (platform_get_entropy(entropy_buf, sizeof(entropy_buf)) == STUTTER_OK) {
            accumulator_add(&g_accumulator, 0, entropy_buf,
                            sizeof(entropy_buf), 8);
            platform_secure_zero(entropy_buf, sizeof(entropy_buf));
        }

        result = accumulator_reseed(&g_accumulator, seed);
    }

    if (result == STUTTER_OK) {
        generator_reseed(gen, seed);
        platform_secure_zero(seed, sizeof(seed));
    } else {
        /* Failed to seed generator. This is a critical error. */
        free(gen);
        return NULL;
    }

    pthread_setspecific(g_generator_key, gen);

    STUTTER_LOG("Created thread-local generator");

    return gen;
}

/* ============================================================================
 * Public API: Lifecycle
 * ============================================================================ */

int stutter_init(void)
{
    int result;
    int pool0_entropy;

    pthread_mutex_lock(&g_init_mutex);

    if (g_initialized) {
        pthread_mutex_unlock(&g_init_mutex);
        return STUTTER_OK;
    }

    STUTTER_LOG("Initializing Stutter CSPRNG...");

    /* Initialize TLS key */
    pthread_once(&g_tls_init_once, tls_init);

    /* Initialize accumulator */
    accumulator_init(&g_accumulator);

    /* Initialize entropy subsystem */
    result = entropy_init();
    if (result != STUTTER_OK) {
        accumulator_shutdown(&g_accumulator);
        pthread_mutex_unlock(&g_init_mutex);
        STUTTER_LOG("Failed to initialize entropy subsystem");
        return result;
    }

    /*
     * Block until we have sufficient entropy.
     * This is critical for security: we must not generate
     * random numbers from an unseeded state.
     */
    STUTTER_LOG("Gathering initial entropy (need %d bits)...",
                STUTTER_INIT_THRESHOLD);

    while (1) {
        result = entropy_gather(&g_accumulator, STUTTER_INIT_THRESHOLD);
        if (result != STUTTER_OK) {
            entropy_shutdown();
            accumulator_shutdown(&g_accumulator);
            pthread_mutex_unlock(&g_init_mutex);
            STUTTER_LOG("Failed to gather initial entropy");
            return STUTTER_ERR_NO_ENTROPY;
        }

        pool0_entropy = accumulator_get_entropy_estimate(&g_accumulator, 0);
        if (pool0_entropy >= (int)STUTTER_INIT_THRESHOLD) {
            break;
        }

        STUTTER_LOG("Pool 0 has %d bits, need %d, continuing...",
                    pool0_entropy, STUTTER_INIT_THRESHOLD);
    }

    g_initialized = 1;

    pthread_mutex_unlock(&g_init_mutex);

    STUTTER_LOG("Stutter CSPRNG initialized successfully");

    return STUTTER_OK;
}

void stutter_shutdown(void)
{
    pthread_mutex_lock(&g_init_mutex);

    if (!g_initialized) {
        pthread_mutex_unlock(&g_init_mutex);
        return;
    }

    STUTTER_LOG("Shutting down Stutter CSPRNG...");

    /*
     * Clean up calling thread's generator.
     *
     * IMPORTANT: We do NOT call pthread_key_delete here. Per POSIX,
     * pthread_key_delete does NOT invoke destructors for existing
     * thread-specific values. If we delete the key, threads that exit
     * after shutdown will NOT have their destructors called, causing
     * key material to leak permanently.
     *
     * By leaving the key intact, threads that exit after shutdown will
     * still have their destructor called to clean up their generator.
     *
     * SECURITY NOTE: For maximum security, applications should ensure
     * all threads using stutter have terminated before calling
     * stutter_shutdown(). This guarantees all key material is wiped.
     */
    {
        stutter_generator_t *gen;
        gen = (stutter_generator_t *)pthread_getspecific(g_generator_key);
        if (gen != NULL) {
            generator_shutdown(gen);
            platform_secure_zero(gen, sizeof(*gen));
            free(gen);
            pthread_setspecific(g_generator_key, NULL);
        }
    }

    /*
     * Reset pthread_once control to allow re-initialization.
     * This is necessary for applications that may call stutter_init()
     * again after shutdown (e.g., in test suites).
     *
     * Note: The TLS key remains valid. Re-initialization will create
     * a new key via pthread_once, but the old key's destructor will
     * still be called for any threads that exit.
     */
    {
        pthread_once_t reset = PTHREAD_ONCE_INIT;
        g_tls_init_once = reset;
    }

    entropy_shutdown();
    accumulator_shutdown(&g_accumulator);

    g_initialized = 0;

    pthread_mutex_unlock(&g_init_mutex);

    STUTTER_LOG("Stutter CSPRNG shutdown complete");
}

/* ============================================================================
 * Public API: Random Generation
 * ============================================================================ */

int stutter_rand(void *buf, size_t len)
{
    stutter_generator_t *gen;
    unsigned char seed[32];
    int result;

    if (!g_initialized) {
        return STUTTER_ERR_NOT_INIT;
    }

    if (buf == NULL) {
        return STUTTER_ERR_INVALID;
    }

    if (len == 0) {
        return STUTTER_OK;
    }

    if (len > STUTTER_MAX_REQUEST) {
        return STUTTER_ERR_INVALID;
    }

    gen = get_thread_generator();
    if (gen == NULL) {
        return STUTTER_ERR_MEMORY;
    }

    /* Check if generator needs reseed */
    if (gen->bytes_remaining == 0) {
        int attempts;
        unsigned char entropy_buf[64];

        /*
         * Gather more entropy and reseed. Add directly to pool 0.
         */
        result = STUTTER_ERR_NO_ENTROPY;
        for (attempts = 0; attempts < 10 && result == STUTTER_ERR_NO_ENTROPY; attempts++) {
            if (platform_get_entropy(entropy_buf, sizeof(entropy_buf)) == STUTTER_OK) {
                accumulator_add(&g_accumulator, 0, entropy_buf,
                                sizeof(entropy_buf), 8);
            }
            result = accumulator_reseed(&g_accumulator, seed);
        }
        platform_secure_zero(entropy_buf, sizeof(entropy_buf));

        if (result != STUTTER_OK) {
            return result;
        }

        generator_reseed(gen, seed);
        platform_secure_zero(seed, sizeof(seed));
    }

    return generator_read(gen, buf, len);
}

int stutter_reseed(void)
{
    stutter_generator_t *gen;
    unsigned char seed[32];
    int result;

    if (!g_initialized) {
        return STUTTER_ERR_NOT_INIT;
    }

    gen = get_thread_generator();
    if (gen == NULL) {
        return STUTTER_ERR_MEMORY;
    }

    /* Force entropy gathering directly into pool 0 */
    {
        unsigned char entropy_buf[64];
        int attempts;

        result = STUTTER_ERR_NO_ENTROPY;
        for (attempts = 0; attempts < 10 && result == STUTTER_ERR_NO_ENTROPY; attempts++) {
            if (platform_get_entropy(entropy_buf, sizeof(entropy_buf)) == STUTTER_OK) {
                accumulator_add(&g_accumulator, 0, entropy_buf,
                                sizeof(entropy_buf), 8);
            }
            result = accumulator_reseed(&g_accumulator, seed);
        }
        platform_secure_zero(entropy_buf, sizeof(entropy_buf));

        if (result != STUTTER_OK) {
            return result;
        }
    }

    generator_reseed(gen, seed);
    platform_secure_zero(seed, sizeof(seed));

    return STUTTER_OK;
}

/* ============================================================================
 * Public API: Entropy Management
 * ============================================================================ */

int stutter_entropy_register(const stutter_entropy_source_t *source)
{
    if (!g_initialized) {
        return STUTTER_ERR_NOT_INIT;
    }

    return entropy_register(source);
}

int stutter_entropy_unregister(const char *name)
{
    if (!g_initialized) {
        return STUTTER_ERR_NOT_INIT;
    }

    return entropy_unregister(name);
}

int stutter_add_entropy(unsigned int pool, const void *data, size_t len)
{
    if (!g_initialized) {
        return STUTTER_ERR_NOT_INIT;
    }

    if (data == NULL || len == 0) {
        return STUTTER_ERR_INVALID;
    }

    if (pool >= STUTTER_NUM_POOLS) {
        return STUTTER_ERR_INVALID;
    }

    /* Use quality of 4 bits/byte for externally provided entropy
     * (conservative estimate since we don't know the source quality) */
    accumulator_add(&g_accumulator, pool, data, len, 4);

    return STUTTER_OK;
}

/* ============================================================================
 * Public API: Status
 * ============================================================================ */

int stutter_is_seeded(void)
{
    stutter_generator_t *gen;

    if (!g_initialized) {
        return 0;
    }

    gen = (stutter_generator_t *)pthread_getspecific(g_generator_key);
    if (gen == NULL) {
        /* No generator yet, but library is initialized */
        return 1;
    }

    return gen->seeded;
}

int stutter_get_reseed_count(void)
{
    if (!g_initialized) {
        return 0;
    }

    return (int)g_accumulator.reseed_count;
}
