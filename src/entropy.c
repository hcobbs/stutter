/*
 * entropy.c - Pluggable entropy source management
 *
 * Part of the Stutter CSPRNG library.
 * Copyright (C) 2024
 * SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * [LLM-ARCH] Generated with human review
 *
 * Manages registered entropy sources and distributes entropy
 * to the accumulator pools using round-robin scheduling.
 */

#include "stutter_internal.h"
#include "secure_mem.h"
#include <string.h>

/* Registered entropy sources */
static stutter_entropy_source_t *g_sources[STUTTER_MAX_SOURCES];
static int g_source_count = 0;
static pthread_mutex_t g_entropy_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Pool rotation counter for round-robin distribution */
static unsigned int g_pool_counter = 0;

/* ============================================================================
 * Built-in entropy source: /dev/urandom
 * ============================================================================ */

static int urandom_init(void *ctx)
{
    (void)ctx;
    return STUTTER_OK;
}

static int urandom_read(void *ctx, void *buf, size_t len, size_t *actual)
{
    int result;
    (void)ctx;

    result = platform_get_entropy(buf, len);
    if (result == STUTTER_OK) {
        *actual = len;
    } else {
        *actual = 0;
    }
    return result;
}

static void urandom_shutdown(void *ctx)
{
    (void)ctx;
}

static stutter_entropy_source_t builtin_urandom = {
    "urandom",
    urandom_init,
    urandom_read,
    urandom_shutdown,
    NULL,
    8,      /* Full entropy: 8 bits per byte */
    0,      /* Round-robin pool selection */
    0       /* Call count */
};

/* ============================================================================
 * Built-in entropy source: timing jitter
 * ============================================================================ */

static int jitter_init(void *ctx)
{
    (void)ctx;
    return STUTTER_OK;
}

static int jitter_read(void *ctx, void *buf, size_t len, size_t *actual)
{
    unsigned char *p = (unsigned char *)buf;
    unsigned long t1, t2;
    size_t i;
    (void)ctx;

    /*
     * Collect timing jitter by measuring clock variations.
     * Each byte represents the low bits of timing difference.
     * Quality is low (1-2 bits per byte) but adds defense in depth.
     */
    for (i = 0; i < len; i++) {
        if (platform_get_time_ns(&t1) != STUTTER_OK) {
            *actual = i;
            if (i == 0) {
                return STUTTER_ERR_PLATFORM;
            }
            return STUTTER_OK;
        }

        /* Burn some cycles to create variation */
        {
            volatile int j;
            for (j = 0; j < 100; j++) {
                /* Empty loop - timing variation from cache, interrupts, etc. */
            }
        }

        if (platform_get_time_ns(&t2) != STUTTER_OK) {
            *actual = i;
            if (i == 0) {
                return STUTTER_ERR_PLATFORM;
            }
            return STUTTER_OK;
        }

        /* Use low bits of timing difference */
        p[i] = (unsigned char)(t2 - t1);
    }

    *actual = len;
    return STUTTER_OK;
}

static void jitter_shutdown(void *ctx)
{
    (void)ctx;
}

static stutter_entropy_source_t builtin_jitter = {
    "jitter",
    jitter_init,
    jitter_read,
    jitter_shutdown,
    NULL,
    2,      /* Low entropy: ~2 bits per byte */
    0,      /* Round-robin pool selection */
    0       /* Call count */
};

/* ============================================================================
 * Entropy source management API
 * ============================================================================ */

int entropy_init(void)
{
    int result;

    pthread_mutex_lock(&g_entropy_mutex);

    g_source_count = 0;
    g_pool_counter = 0;

    pthread_mutex_unlock(&g_entropy_mutex);

    /* Register built-in sources */
    result = entropy_register(&builtin_urandom);
    if (result != STUTTER_OK) {
        return result;
    }

    result = entropy_register(&builtin_jitter);
    if (result != STUTTER_OK) {
        return result;
    }

    STUTTER_LOG("Entropy subsystem initialized with %d sources", g_source_count);

    return STUTTER_OK;
}

int entropy_register(const stutter_entropy_source_t *source)
{
    stutter_entropy_source_t *copy;
    char *name_copy;
    size_t name_len;
    int result;

    if (source == NULL || source->name == NULL || source->read == NULL) {
        return STUTTER_ERR_INVALID;
    }

    pthread_mutex_lock(&g_entropy_mutex);

    if (g_source_count >= STUTTER_MAX_SOURCES) {
        pthread_mutex_unlock(&g_entropy_mutex);
        return STUTTER_ERR_INVALID;
    }

    /* Allocate copy of source descriptor from secure memory */
    copy = (stutter_entropy_source_t *)secure_mem_alloc(sizeof(*copy));
    if (copy == NULL) {
        pthread_mutex_unlock(&g_entropy_mutex);
        return STUTTER_ERR_MEMORY;
    }

    /* Copy the name string from secure memory */
    name_len = strlen(source->name);
    name_copy = (char *)secure_mem_alloc(name_len + 1);
    if (name_copy == NULL) {
        secure_mem_free(copy);
        pthread_mutex_unlock(&g_entropy_mutex);
        return STUTTER_ERR_MEMORY;
    }
    memcpy(name_copy, source->name, name_len + 1);

    memcpy(copy, source, sizeof(*copy));
    copy->name = name_copy;
    copy->call_count = 0;

    /* Initialize source if needed */
    if (copy->init != NULL) {
        result = copy->init(copy->ctx);
        if (result != STUTTER_OK) {
            secure_mem_free((void *)copy->name);
            secure_mem_free(copy);
            pthread_mutex_unlock(&g_entropy_mutex);
            return result;
        }
    }

    g_sources[g_source_count] = copy;
    g_source_count++;

    pthread_mutex_unlock(&g_entropy_mutex);

    STUTTER_LOG("Registered entropy source: %s (quality=%u)",
                source->name, source->quality);

    return STUTTER_OK;
}

int entropy_unregister(const char *name)
{
    int i;
    int found;

    if (name == NULL) {
        return STUTTER_ERR_INVALID;
    }

    pthread_mutex_lock(&g_entropy_mutex);

    found = -1;
    for (i = 0; i < g_source_count; i++) {
        if (strcmp(g_sources[i]->name, name) == 0) {
            found = i;
            break;
        }
    }

    if (found < 0) {
        pthread_mutex_unlock(&g_entropy_mutex);
        return STUTTER_ERR_INVALID;
    }

    /* Shutdown source */
    if (g_sources[found]->shutdown != NULL) {
        g_sources[found]->shutdown(g_sources[found]->ctx);
    }

    /* Free the copied name string from secure memory */
    secure_mem_free((void *)g_sources[found]->name);
    secure_mem_free(g_sources[found]);

    /* Shift remaining sources down */
    for (i = found; i < g_source_count - 1; i++) {
        g_sources[i] = g_sources[i + 1];
    }
    g_source_count--;

    pthread_mutex_unlock(&g_entropy_mutex);

    STUTTER_LOG("Unregistered entropy source: %s", name);

    return STUTTER_OK;
}

int entropy_gather(stutter_accumulator_t *acc, size_t min_bits)
{
    unsigned char buf[STUTTER_ENTROPY_BUF_SIZE];
    size_t actual;
    size_t total_bits;
    unsigned int pool;
    unsigned int quality;
    int i;
    int result;
    int source_count_snapshot;

    if (acc == NULL) {
        return STUTTER_ERR_INVALID;
    }

    pthread_mutex_lock(&g_entropy_mutex);

    if (g_source_count == 0) {
        pthread_mutex_unlock(&g_entropy_mutex);
        return STUTTER_ERR_NO_ENTROPY;
    }

    total_bits = 0;

    /*
     * Gather from all sources until we have enough entropy.
     * Keep cycling through sources until min_bits is reached.
     *
     * THREAD SAFETY: The mutex is held for the entire gather operation
     * (acquired at line 290). This prevents source registration/unregistration
     * during gathering. The snapshot and bounds check are defensive measures
     * that are currently unreachable due to mutex protection.
     */
    while (total_bits < min_bits) {
        source_count_snapshot = g_source_count;
        for (i = 0; i < source_count_snapshot && total_bits < min_bits; i++) {
            stutter_entropy_source_t *src;

            /* Defensive bounds check (unreachable while mutex is held) */
            if (i >= g_source_count) {
                break;
            }
            src = g_sources[i];

            /* Read entropy from source */
            result = src->read(src->ctx, buf, sizeof(buf), &actual);
            if (result != STUTTER_OK || actual == 0) {
                continue;
            }

            /* Determine target pool */
            if (src->pool_mask != 0) {
                /* Use specified pool mask */
                pool = src->call_count % STUTTER_NUM_POOLS;
                while ((src->pool_mask & (1U << pool)) == 0) {
                    pool = (pool + 1) % STUTTER_NUM_POOLS;
                }
            } else {
                /* Round-robin across all pools */
                pool = g_pool_counter % STUTTER_NUM_POOLS;
                g_pool_counter++;
            }

            src->call_count++;
            quality = src->quality;

            /*
             * Add to accumulator while holding mutex.
             * This is safe because accumulator_add only acquires
             * per-pool spinlocks, not the entropy mutex.
             */
            accumulator_add(acc, pool, buf, actual, quality);

            total_bits += actual * quality;
        }

        /* Avoid infinite loop if no sources are producing */
        if (total_bits == 0) {
            break;
        }
    }

    pthread_mutex_unlock(&g_entropy_mutex);

    /* Zero buffer */
    platform_secure_zero(buf, sizeof(buf));

    if (total_bits >= min_bits) {
        STUTTER_LOG("Gathered %zu bits of entropy (requested %zu)",
                    total_bits, min_bits);
        return STUTTER_OK;
    }

    return STUTTER_ERR_NO_ENTROPY;
}

void entropy_shutdown(void)
{
    int i;

    pthread_mutex_lock(&g_entropy_mutex);

    for (i = 0; i < g_source_count; i++) {
        if (g_sources[i]->shutdown != NULL) {
            g_sources[i]->shutdown(g_sources[i]->ctx);
        }
        /* Free from secure memory */
        secure_mem_free((void *)g_sources[i]->name);
        secure_mem_free(g_sources[i]);
        g_sources[i] = NULL;
    }

    g_source_count = 0;
    g_pool_counter = 0;

    pthread_mutex_unlock(&g_entropy_mutex);

    STUTTER_LOG("Entropy subsystem shutdown complete");
}
