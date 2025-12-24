/*
 * secure_mem.c - RAMPart-backed secure memory management
 *
 * Part of the Stutter CSPRNG library.
 * Copyright (C) 2024
 * SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * [LLM-ARCH] RAMPart integration
 *
 * Provides RAMPart pool management for all internal allocations.
 */

#include "secure_mem.h"
#include "stutter_internal.h"
#include <stdlib.h>

/* ============================================================================
 * Global Pool
 * ============================================================================ */

static rampart_pool_t *g_global_pool = NULL;

int secure_mem_init(void)
{
    rampart_config_t config;
    rampart_error_t err;

    if (g_global_pool != NULL) {
        return STUTTER_OK;
    }

    err = rampart_config_default(&config);
    if (err != RAMPART_OK) {
        return STUTTER_ERR_RAMPART;
    }

    config.pool_size = STUTTER_GLOBAL_POOL_SIZE;
    config.strict_thread_mode = 0;  /* Multiple threads access */
    config.enable_parking = 0;      /* No parking for global state */

    g_global_pool = rampart_init(&config);
    if (g_global_pool == NULL) {
        return STUTTER_ERR_RAMPART;
    }

    STUTTER_LOG("Global secure memory pool initialized (%zu bytes)",
                (size_t)STUTTER_GLOBAL_POOL_SIZE);

    return STUTTER_OK;
}

void secure_mem_shutdown(void)
{
    rampart_shutdown_result_t result;

    if (g_global_pool == NULL) {
        return;
    }

    result = rampart_shutdown(g_global_pool);
    g_global_pool = NULL;

    if (result.leaked_blocks > 0) {
        STUTTER_LOG("WARNING: %zu blocks leaked from global pool (%zu bytes)",
                    result.leaked_blocks, result.leaked_bytes);
    }

    STUTTER_LOG("Global secure memory pool shutdown");
}

void *secure_mem_alloc(size_t size)
{
    if (g_global_pool == NULL || size == 0) {
        return NULL;
    }

    return rampart_alloc(g_global_pool, size);
}

void secure_mem_free(void *ptr)
{
    if (g_global_pool == NULL || ptr == NULL) {
        return;
    }

    rampart_free(g_global_pool, ptr);
}

/* ============================================================================
 * Thread-Local Pools
 * ============================================================================ */

stutter_tls_t *secure_mem_tls_create(void)
{
    stutter_tls_t *tls;
    rampart_config_t config;
    rampart_error_t err;

    /*
     * Allocate TLS structure from system heap.
     * This is intentional: the TLS structure itself is small and
     * needs to exist before the pool is created.
     */
    tls = (stutter_tls_t *)malloc(sizeof(*tls));
    if (tls == NULL) {
        return NULL;
    }

    tls->generator = NULL;
    tls->parked = 0;

    err = rampart_config_default(&config);
    if (err != RAMPART_OK) {
        free(tls);
        return NULL;
    }

    config.pool_size = STUTTER_TLS_POOL_SIZE;
    config.strict_thread_mode = 1;  /* Single thread only */
    config.enable_parking = 1;      /* Key parking enabled */

    tls->pool = rampart_init(&config);
    if (tls->pool == NULL) {
        free(tls);
        return NULL;
    }

    STUTTER_LOG("Thread-local secure memory pool created (%zu bytes)",
                (size_t)STUTTER_TLS_POOL_SIZE);

    return tls;
}

void secure_mem_tls_destroy(stutter_tls_t *tls)
{
    rampart_shutdown_result_t result;

    if (tls == NULL) {
        return;
    }

    if (tls->pool != NULL) {
        result = rampart_shutdown(tls->pool);
        tls->pool = NULL;

        if (result.leaked_blocks > 0) {
            STUTTER_LOG("WARNING: %zu blocks leaked from TLS pool (%zu bytes)",
                        result.leaked_blocks, result.leaked_bytes);
        }
    }

    free(tls);

    STUTTER_LOG("Thread-local secure memory pool destroyed");
}

void *secure_mem_tls_alloc(stutter_tls_t *tls, size_t size)
{
    if (tls == NULL || tls->pool == NULL || size == 0) {
        return NULL;
    }

    return rampart_alloc(tls->pool, size);
}

void secure_mem_tls_free(stutter_tls_t *tls, void *ptr)
{
    if (tls == NULL || tls->pool == NULL || ptr == NULL) {
        return;
    }

    rampart_free(tls->pool, ptr);
}

int secure_mem_tls_park(stutter_tls_t *tls, void *ptr)
{
    rampart_error_t err;

    if (tls == NULL || tls->pool == NULL || ptr == NULL) {
        return STUTTER_ERR_INVALID;
    }

    err = rampart_park(tls->pool, ptr);
    if (err != RAMPART_OK) {
        return STUTTER_ERR_RAMPART;
    }

    return STUTTER_OK;
}

int secure_mem_tls_unpark(stutter_tls_t *tls, void *ptr)
{
    rampart_error_t err;

    if (tls == NULL || tls->pool == NULL || ptr == NULL) {
        return STUTTER_ERR_INVALID;
    }

    err = rampart_unpark(tls->pool, ptr);
    if (err != RAMPART_OK) {
        return STUTTER_ERR_RAMPART;
    }

    return STUTTER_OK;
}

int secure_mem_tls_is_parked(stutter_tls_t *tls, void *ptr)
{
    if (tls == NULL || tls->pool == NULL || ptr == NULL) {
        return 0;
    }

    return rampart_is_parked(tls->pool, ptr);
}
