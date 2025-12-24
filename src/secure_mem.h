/*
 * secure_mem.h - Internal secure memory management API
 *
 * Part of the Stutter CSPRNG library.
 * Copyright (C) 2024
 * SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * [LLM-ARCH] RAMPart integration
 *
 * This module provides RAMPart-backed memory allocation for all
 * internal Stutter allocations. Two pool types are used:
 *
 * - Global pool: For shared state (entropy sources). Multi-thread safe.
 * - Thread-local pools: For generators. Single-thread, parking enabled.
 */

#ifndef STUTTER_SECURE_MEM_H
#define STUTTER_SECURE_MEM_H

#include <stddef.h>
#include <rampart.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Configuration (compile-time overridable)
 * ============================================================================ */

#ifndef STUTTER_GLOBAL_POOL_SIZE
#define STUTTER_GLOBAL_POOL_SIZE    (64 * 1024)
#endif

#ifndef STUTTER_TLS_POOL_SIZE
#define STUTTER_TLS_POOL_SIZE       (8 * 1024)
#endif

/* ============================================================================
 * Global Pool Management
 * ============================================================================ */

/*
 * Initialize the global RAMPart pool.
 *
 * Called during stutter_init(). The global pool is used for:
 * - Entropy source descriptors
 * - Source name strings
 *
 * Configuration:
 * - strict_thread_mode = 0 (multiple threads access)
 * - enable_parking = 0 (no parking for global state)
 *
 * Returns: STUTTER_OK on success, error code on failure.
 */
int secure_mem_init(void);

/*
 * Shutdown the global RAMPart pool.
 *
 * Called during stutter_shutdown(). Reports any leaked allocations.
 */
void secure_mem_shutdown(void);

/*
 * Allocate memory from the global pool.
 *
 * Parameters:
 *   size - Number of bytes to allocate
 *
 * Returns: Pointer to zero-initialized memory, or NULL on failure.
 */
void *secure_mem_alloc(size_t size);

/*
 * Free memory back to the global pool.
 *
 * Memory is securely wiped before being returned to the free list.
 *
 * Parameters:
 *   ptr - Pointer to memory to free (as returned by secure_mem_alloc)
 */
void secure_mem_free(void *ptr);

/* ============================================================================
 * Thread-Local Pool Management
 * ============================================================================ */

/*
 * Thread-local state structure.
 *
 * Each thread has its own pool for generator allocations.
 * This enables strict thread ownership and key parking.
 */
typedef struct {
    rampart_pool_t *pool;           /* Thread-local RAMPart pool */
    void *generator;                /* Generator allocated from pool */
    int parked;                     /* Is generator currently parked? */
} stutter_tls_t;

/*
 * Create a thread-local pool.
 *
 * Configuration:
 * - strict_thread_mode = 1 (single thread only)
 * - enable_parking = 1 (key parking enabled)
 *
 * Returns: Pointer to initialized TLS structure, or NULL on failure.
 */
stutter_tls_t *secure_mem_tls_create(void);

/*
 * Destroy a thread-local pool.
 *
 * Unparks any parked blocks, securely wipes, and releases resources.
 *
 * Parameters:
 *   tls - TLS structure to destroy (may be NULL)
 */
void secure_mem_tls_destroy(stutter_tls_t *tls);

/*
 * Allocate memory from a thread-local pool.
 *
 * Parameters:
 *   tls  - TLS structure
 *   size - Number of bytes to allocate
 *
 * Returns: Pointer to zero-initialized memory, or NULL on failure.
 */
void *secure_mem_tls_alloc(stutter_tls_t *tls, size_t size);

/*
 * Free memory back to a thread-local pool.
 *
 * Parameters:
 *   tls - TLS structure
 *   ptr - Pointer to memory to free
 */
void secure_mem_tls_free(stutter_tls_t *tls, void *ptr);

/*
 * Park a block in a thread-local pool.
 *
 * Encrypts the block's contents in memory using ChaCha20.
 *
 * Parameters:
 *   tls - TLS structure
 *   ptr - Pointer to block to park
 *
 * Returns: STUTTER_OK on success, error code on failure.
 */
int secure_mem_tls_park(stutter_tls_t *tls, void *ptr);

/*
 * Unpark a block in a thread-local pool.
 *
 * Decrypts the block's contents.
 *
 * Parameters:
 *   tls - TLS structure
 *   ptr - Pointer to block to unpark
 *
 * Returns: STUTTER_OK on success, error code on failure.
 */
int secure_mem_tls_unpark(stutter_tls_t *tls, void *ptr);

/*
 * Check if a block is parked.
 *
 * Parameters:
 *   tls - TLS structure
 *   ptr - Pointer to block to check
 *
 * Returns: 1 if parked, 0 otherwise.
 */
int secure_mem_tls_is_parked(stutter_tls_t *tls, void *ptr);

#ifdef __cplusplus
}
#endif

#endif /* STUTTER_SECURE_MEM_H */
