/*
 * stutter.h - Public API for Stutter CSPRNG
 *
 * Part of the Stutter CSPRNG library.
 * Copyright (C) 2024
 * SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * Stutter is a Fortuna-based cryptographically secure pseudorandom
 * number generator (CSPRNG) with the following properties:
 *
 * - Backtrack Resistance: Compromised state cannot recover previous output
 * - Prediction Resistance: Fresh entropy prevents forward prediction
 * - Thread Safety: Hierarchical locking with thread-local generators
 * - Pluggable Entropy: Register custom entropy sources
 */

#ifndef STUTTER_H
#define STUTTER_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Error Codes
 * ============================================================================ */

#define STUTTER_OK              0   /* Success */
#define STUTTER_ERR_NOT_INIT   -1   /* Library not initialized */
#define STUTTER_ERR_NO_ENTROPY -2   /* Insufficient entropy available */
#define STUTTER_ERR_INVALID    -3   /* Invalid parameter */
#define STUTTER_ERR_LOCKED     -4   /* Resource locked (internal) */
#define STUTTER_ERR_MEMORY     -5   /* Memory allocation failed */
#define STUTTER_ERR_PLATFORM   -6   /* Platform-specific error */

/* ============================================================================
 * Library Lifecycle
 * ============================================================================ */

/*
 * Initialize the Stutter CSPRNG library.
 *
 * This function blocks until sufficient entropy has been gathered
 * (at least 256 bits in pool 0). On a system with /dev/urandom,
 * this typically completes immediately.
 *
 * Returns: STUTTER_OK on success, error code on failure.
 */
int stutter_init(void);

/*
 * Shutdown the Stutter CSPRNG library.
 *
 * Securely zeros all internal state and releases resources.
 * Thread-local generators are cleaned up automatically when
 * their threads exit.
 */
void stutter_shutdown(void);

/* ============================================================================
 * Random Generation
 * ============================================================================ */

/*
 * Generate cryptographically secure random bytes.
 *
 * This is the primary interface for obtaining random data.
 * Each thread uses its own generator, automatically reseeding
 * when the quota (64KB) is exhausted.
 *
 * Parameters:
 *   buf - Buffer to receive random bytes
 *   len - Number of bytes to generate (max 1MB)
 *
 * Returns: STUTTER_OK on success, error code on failure.
 */
int stutter_rand(void *buf, size_t len);

/*
 * Force an immediate reseed of the current thread's generator.
 *
 * Gathers fresh entropy and performs a reseed operation.
 * This is useful after potentially compromising events or
 * when additional security margin is desired.
 *
 * Returns: STUTTER_OK on success, error code on failure.
 */
int stutter_reseed(void);

/* ============================================================================
 * Entropy Source Management
 * ============================================================================ */

/*
 * Entropy source descriptor.
 *
 * Users can register custom entropy sources by providing this structure.
 * The library takes a copy, so the original can be freed after registration.
 */
typedef struct stutter_entropy_source {
    const char *name;           /* Human-readable name (required) */

    /*
     * Initialize the entropy source.
     * Called once when the source is registered.
     * May be NULL if no initialization is needed.
     */
    int (*init)(void *ctx);

    /*
     * Read entropy from the source.
     * Must write up to len bytes to buf and set *actual to bytes written.
     * Required.
     */
    int (*read)(void *ctx, void *buf, size_t len, size_t *actual);

    /*
     * Shutdown the entropy source.
     * Called when the source is unregistered or library shuts down.
     * May be NULL if no cleanup is needed.
     */
    void (*shutdown)(void *ctx);

    void *ctx;                  /* Opaque context passed to callbacks */
    unsigned int quality;       /* Estimated bits of entropy per byte (0-8) */
    unsigned int pool_mask;     /* Bitmask of target pools (0 = round-robin) */
    unsigned int call_count;    /* Internal: do not modify */
} stutter_entropy_source_t;

/*
 * Register a custom entropy source.
 *
 * The library copies the descriptor, so it may be freed after registration.
 * Up to 16 sources can be registered.
 *
 * Returns: STUTTER_OK on success, error code on failure.
 */
int stutter_entropy_register(const stutter_entropy_source_t *source);

/*
 * Unregister an entropy source by name.
 *
 * Returns: STUTTER_OK on success, STUTTER_ERR_INVALID if not found.
 */
int stutter_entropy_unregister(const char *name);

/*
 * Manually add entropy to a specific pool.
 *
 * Useful for injecting application-specific entropy (user input timing,
 * network packet timing, hardware events, etc.).
 *
 * Parameters:
 *   pool - Target pool (0-31)
 *   data - Entropy data
 *   len  - Length of data
 *
 * Returns: STUTTER_OK on success, error code on failure.
 */
int stutter_add_entropy(unsigned int pool, const void *data, size_t len);

/* ============================================================================
 * Status
 * ============================================================================ */

/*
 * Check if the library is properly seeded.
 *
 * Returns 1 if seeded and ready to generate, 0 otherwise.
 */
int stutter_is_seeded(void);

/*
 * Get the total number of reseeds performed.
 *
 * Useful for monitoring and debugging.
 */
int stutter_get_reseed_count(void);

#ifdef __cplusplus
}
#endif

#endif /* STUTTER_H */
