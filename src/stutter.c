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
#include "secure_mem.h"
#include <stdlib.h>

/* ============================================================================
 * Global State
 * ============================================================================ */

static stutter_accumulator_t g_accumulator;
static pthread_key_t g_generator_key;
static pthread_mutex_t g_init_mutex = PTHREAD_MUTEX_INITIALIZER;
static volatile int g_initialized = 0;
static int g_tls_key_created = 0;
static volatile int g_shutdown_complete = 0;  /* Guards TLS destructor after shutdown */

/* ============================================================================
 * Thread-Local Generator Management
 * ============================================================================ */

static void tls_destructor(void *ptr)
{
    stutter_tls_t *tls = (stutter_tls_t *)ptr;
    if (tls == NULL) {
        return;
    }

    /*
     * If global shutdown has completed, RAMPart pools are gone.
     * We can only do minimal cleanup (secure wipe via generator_shutdown).
     * The TLS struct itself was heap-allocated so we still free it.
     */
    if (g_shutdown_complete) {
        if (tls->generator != NULL) {
            generator_shutdown((stutter_generator_t *)tls->generator);
            /* Cannot call secure_mem_tls_free - pool is gone */
        }
        /* Cannot call secure_mem_tls_destroy - pool is gone, but free TLS struct */
        free(tls);
        return;
    }

    if (tls->generator != NULL) {
        stutter_generator_t *gen = (stutter_generator_t *)tls->generator;
        /* Unpark if parked before cleanup */
        if (tls->parked) {
            secure_mem_tls_unpark(tls, gen);
            tls->parked = 0;
        }
        generator_shutdown(gen);
        secure_mem_tls_free(tls, gen);
    }
    secure_mem_tls_destroy(tls);
}

/*
 * Initialize TLS key for thread-local generators.
 * Returns STUTTER_OK on success or if already initialized.
 */
static int tls_init(void)
{
    if (g_tls_key_created) {
        return STUTTER_OK;
    }

    if (pthread_key_create(&g_generator_key, tls_destructor) != 0) {
        return STUTTER_ERR_PLATFORM;
    }

    g_tls_key_created = 1;
    return STUTTER_OK;
}

/*
 * Gather entropy and reseed the accumulator.
 * Tries up to STUTTER_RESEED_ATTEMPTS times to gather enough entropy.
 * On success, writes the 32-byte seed to the provided buffer.
 *
 * Returns: STUTTER_OK on success, error code on failure.
 */
static int gather_and_reseed(unsigned char seed[32])
{
    unsigned char entropy_buf[STUTTER_ENTROPY_BUF_SIZE];
    int result;
    int attempts;

    result = STUTTER_ERR_NO_ENTROPY;
    for (attempts = 0;
         attempts < STUTTER_RESEED_ATTEMPTS && result == STUTTER_ERR_NO_ENTROPY;
         attempts++) {
        if (platform_get_entropy(entropy_buf, sizeof(entropy_buf)) == STUTTER_OK) {
            accumulator_add(&g_accumulator, 0, entropy_buf,
                            sizeof(entropy_buf), 8);
        }
        result = accumulator_reseed(&g_accumulator, seed);
    }

    platform_secure_zero(entropy_buf, sizeof(entropy_buf));
    return result;
}

static stutter_tls_t *get_thread_state(void)
{
    stutter_tls_t *tls;
    stutter_generator_t *gen;
    unsigned char seed[32];
    int result;

    tls = (stutter_tls_t *)pthread_getspecific(g_generator_key);
    if (tls != NULL) {
        return tls;
    }

    /* Create new TLS structure with RAMPart pool */
    tls = secure_mem_tls_create();
    if (tls == NULL) {
        return NULL;
    }

    /* Allocate generator from thread-local pool */
    gen = (stutter_generator_t *)secure_mem_tls_alloc(tls, sizeof(*gen));
    if (gen == NULL) {
        secure_mem_tls_destroy(tls);
        return NULL;
    }

    generator_init(gen);
    tls->generator = gen;
    tls->parked = 0;

    /* Perform initial reseed */
    result = gather_and_reseed(seed);
    if (result != STUTTER_OK) {
        secure_mem_tls_free(tls, gen);
        secure_mem_tls_destroy(tls);
        return NULL;
    }

    result = generator_reseed(gen, seed);
    platform_secure_zero(seed, sizeof(seed));
    if (result != STUTTER_OK) {
        /* Failed to seed generator. This is a critical error. */
        secure_mem_tls_free(tls, gen);
        secure_mem_tls_destroy(tls);
        return NULL;
    }

    pthread_setspecific(g_generator_key, tls);

    STUTTER_LOG("Created thread-local generator with secure memory pool");

    return tls;
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

    /* Reset shutdown flag for re-initialization */
    g_shutdown_complete = 0;

    /* Initialize secure memory (RAMPart global pool) */
    result = secure_mem_init();
    if (result != STUTTER_OK) {
        pthread_mutex_unlock(&g_init_mutex);
        STUTTER_LOG("Failed to initialize secure memory");
        return result;
    }

    /* Initialize TLS key */
    result = tls_init();
    if (result != STUTTER_OK) {
        secure_mem_shutdown();
        pthread_mutex_unlock(&g_init_mutex);
        STUTTER_LOG("Failed to create TLS key");
        return result;
    }

    /* Initialize accumulator */
    accumulator_init(&g_accumulator);

    /* Initialize entropy subsystem */
    result = entropy_init();
    if (result != STUTTER_OK) {
        accumulator_shutdown(&g_accumulator);
        secure_mem_shutdown();
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
            secure_mem_shutdown();
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
        stutter_tls_t *tls;
        tls = (stutter_tls_t *)pthread_getspecific(g_generator_key);
        if (tls != NULL) {
            if (tls->generator != NULL) {
                stutter_generator_t *gen = (stutter_generator_t *)tls->generator;
                if (tls->parked) {
                    secure_mem_tls_unpark(tls, gen);
                    tls->parked = 0;
                }
                generator_shutdown(gen);
                secure_mem_tls_free(tls, gen);
            }
            secure_mem_tls_destroy(tls);
            pthread_setspecific(g_generator_key, NULL);
        }
    }

    /*
     * Note: We do NOT reset g_tls_key_created or destroy the TLS key.
     * The key remains valid so threads that exit after shutdown still
     * have their destructor called. Re-initialization via stutter_init()
     * will reuse the existing key, which is safe.
     */

    entropy_shutdown();
    accumulator_shutdown(&g_accumulator);
    secure_mem_shutdown();

    /*
     * Mark shutdown complete BEFORE releasing mutex.
     * This prevents TLS destructors from accessing freed RAMPart pools.
     */
    g_shutdown_complete = 1;
    g_initialized = 0;

    pthread_mutex_unlock(&g_init_mutex);

    STUTTER_LOG("Stutter CSPRNG shutdown complete");
}

/* ============================================================================
 * Public API: Random Generation
 * ============================================================================ */

int stutter_rand(void *buf, size_t len)
{
    stutter_tls_t *tls;
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

    tls = get_thread_state();
    if (tls == NULL) {
        return STUTTER_ERR_MEMORY;
    }

    /* Auto-unpark if parked */
    if (tls->parked) {
        result = secure_mem_tls_unpark(tls, tls->generator);
        if (result != STUTTER_OK) {
            return result;
        }
        tls->parked = 0;
        STUTTER_LOG("Generator auto-unparked");
    }

    gen = (stutter_generator_t *)tls->generator;

    /* Check if generator needs reseed */
    if (gen->bytes_remaining == 0) {
        result = gather_and_reseed(seed);
        if (result != STUTTER_OK) {
            return result;
        }

        result = generator_reseed(gen, seed);
        platform_secure_zero(seed, sizeof(seed));
        if (result != STUTTER_OK) {
            return result;
        }
    }

    return generator_read(gen, buf, len);
}

int stutter_reseed(void)
{
    stutter_tls_t *tls;
    stutter_generator_t *gen;
    unsigned char seed[32];
    int result;

    if (!g_initialized) {
        return STUTTER_ERR_NOT_INIT;
    }

    tls = get_thread_state();
    if (tls == NULL) {
        return STUTTER_ERR_MEMORY;
    }

    /* Unpark if parked */
    if (tls->parked) {
        result = secure_mem_tls_unpark(tls, tls->generator);
        if (result != STUTTER_OK) {
            return result;
        }
        tls->parked = 0;
    }

    gen = (stutter_generator_t *)tls->generator;

    result = gather_and_reseed(seed);
    if (result != STUTTER_OK) {
        return result;
    }

    result = generator_reseed(gen, seed);
    platform_secure_zero(seed, sizeof(seed));
    if (result != STUTTER_OK) {
        return result;
    }

    /* Park after reseed with fresh key */
    result = secure_mem_tls_park(tls, tls->generator);
    if (result == STUTTER_OK) {
        tls->parked = 1;
        STUTTER_LOG("Generator parked after manual reseed");
    } else {
        STUTTER_LOG("WARNING: Failed to park generator after reseed (error %d)", result);
    }

    return STUTTER_OK;
}

void *stutter_rand_secure_alloc(size_t len)
{
    stutter_tls_t *tls;
    void *buf;
    int result;

    if (!g_initialized || len == 0) {
        return NULL;
    }

    if (len > STUTTER_MAX_REQUEST) {
        return NULL;
    }

    tls = get_thread_state();
    if (tls == NULL) {
        return NULL;
    }

    /* Allocate from thread-local secure pool */
    buf = secure_mem_tls_alloc(tls, len);
    if (buf == NULL) {
        return NULL;
    }

    /* Fill with random data */
    result = stutter_rand(buf, len);
    if (result != STUTTER_OK) {
        secure_mem_tls_free(tls, buf);
        return NULL;
    }

    return buf;
}

void stutter_rand_secure_free(void *ptr, size_t len)
{
    stutter_tls_t *tls;

    if (ptr == NULL || !g_initialized) {
        return;
    }

    tls = (stutter_tls_t *)pthread_getspecific(g_generator_key);
    if (tls == NULL) {
        return;
    }

    /* Secure wipe before freeing */
    platform_secure_zero(ptr, len);
    secure_mem_tls_free(tls, ptr);
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
    stutter_tls_t *tls;
    stutter_generator_t *gen;

    if (!g_initialized) {
        return 0;
    }

    tls = (stutter_tls_t *)pthread_getspecific(g_generator_key);
    if (tls == NULL) {
        /* No generator yet, but library is initialized */
        return 1;
    }

    gen = (stutter_generator_t *)tls->generator;
    return gen->seeded;
}

int stutter_get_reseed_count(void)
{
    if (!g_initialized) {
        return 0;
    }

    return (int)g_accumulator.reseed_count;
}

/* ============================================================================
 * Public API: Key Parking
 * ============================================================================ */

int stutter_park_generator(void)
{
    stutter_tls_t *tls;
    int result;

    if (!g_initialized) {
        return STUTTER_ERR_NOT_INIT;
    }

    tls = (stutter_tls_t *)pthread_getspecific(g_generator_key);
    if (tls == NULL || tls->generator == NULL) {
        return STUTTER_ERR_NOT_INIT;
    }

    if (tls->parked) {
        return STUTTER_OK;
    }

    result = secure_mem_tls_park(tls, tls->generator);
    if (result == STUTTER_OK) {
        tls->parked = 1;
        STUTTER_LOG("Generator parked");
    }

    return result;
}

int stutter_is_generator_parked(void)
{
    stutter_tls_t *tls;

    if (!g_initialized) {
        return 0;
    }

    tls = (stutter_tls_t *)pthread_getspecific(g_generator_key);
    if (tls == NULL) {
        return 0;
    }

    return tls->parked;
}
