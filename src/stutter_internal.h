/*
 * stutter_internal.h - Internal declarations for Stutter CSPRNG
 *
 * Part of the Stutter CSPRNG library.
 * Copyright (C) 2024
 * SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * [LLM-ARCH] Generated with human review
 */

#ifndef STUTTER_INTERNAL_H
#define STUTTER_INTERNAL_H

#include <stddef.h>
#include <pthread.h>
#include <openssl/evp.h>
#include "../include/stutter.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Constants
 * ============================================================================ */

#define STUTTER_NUM_POOLS       32
#define STUTTER_POOL_THRESHOLD  128     /* Bits in P0 before reseed allowed */
#define STUTTER_INIT_THRESHOLD  256     /* Bits in P0 before init completes */
#define STUTTER_GENERATOR_QUOTA 65536   /* Bytes before forced reseed */
#define STUTTER_MAX_REQUEST     1048576 /* Max bytes per request (1MB) */
#define STUTTER_MAX_SOURCES     16      /* Max registered entropy sources */
#define STUTTER_RESEED_ATTEMPTS 10      /* Max attempts to gather entropy for reseed */
#define STUTTER_ENTROPY_BUF_SIZE 64     /* Bytes to gather per entropy attempt */

#define STUTTER_AES_BLOCK_SIZE  16
#define STUTTER_AES_KEY_SIZE    32
#define STUTTER_SHA256_SIZE     32

/* ============================================================================
 * SHA-256 (OpenSSL EVP wrapper)
 * ============================================================================ */

typedef struct {
    EVP_MD_CTX *ctx;            /* OpenSSL message digest context */
} sha256_ctx_t;

void sha256_init(sha256_ctx_t *ctx);
void sha256_update(sha256_ctx_t *ctx, const void *data, size_t len);
void sha256_final(sha256_ctx_t *ctx, unsigned char digest[32]);
void sha256(const void *data, size_t len, unsigned char digest[32]);

/* ============================================================================
 * AES-256 (OpenSSL EVP wrapper)
 * ============================================================================ */

typedef struct {
    EVP_CIPHER_CTX *ctx;        /* OpenSSL cipher context */
} aes256_ctx_t;

void aes256_init(aes256_ctx_t *ctx, const unsigned char key[32]);
void aes256_encrypt(const aes256_ctx_t *ctx,
                    const unsigned char in[16],
                    unsigned char out[16]);
void aes256_done(aes256_ctx_t *ctx);

/* ============================================================================
 * Generator (AES-256-CTR)
 * ============================================================================ */

typedef struct {
    aes256_ctx_t aes;                           /* Expanded AES key */
    unsigned char key[STUTTER_AES_KEY_SIZE];    /* Current key (for reseed mixing) */
    unsigned char counter[STUTTER_AES_BLOCK_SIZE]; /* 128-bit counter */
    size_t bytes_remaining;                     /* Quota until reseed */
    int seeded;                                 /* Has been seeded */
} stutter_generator_t;

void generator_init(stutter_generator_t *gen);
void generator_reseed(stutter_generator_t *gen, const unsigned char seed[32]);
int  generator_read(stutter_generator_t *gen, void *buf, size_t len);
void generator_shutdown(stutter_generator_t *gen);

/* ============================================================================
 * Accumulator (32-pool Fortuna)
 * ============================================================================ */

/*
 * Portable spinlock abstraction.
 * Uses pthread_spinlock_t on Linux/BSD, mutex fallback on macOS.
 */
#if defined(__linux__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#define STUTTER_HAS_SPINLOCK 1
typedef pthread_spinlock_t stutter_spinlock_t;
#define stutter_spin_init(s)    pthread_spin_init((s), PTHREAD_PROCESS_PRIVATE)
#define stutter_spin_lock(s)    pthread_spin_lock(s)
#define stutter_spin_unlock(s)  pthread_spin_unlock(s)
#define stutter_spin_destroy(s) pthread_spin_destroy(s)
#else
/* macOS and other systems: use mutex as fallback */
#define STUTTER_HAS_SPINLOCK 0
typedef pthread_mutex_t stutter_spinlock_t;
#define stutter_spin_init(s)    pthread_mutex_init((s), NULL)
#define stutter_spin_lock(s)    pthread_mutex_lock(s)
#define stutter_spin_unlock(s)  pthread_mutex_unlock(s)
#define stutter_spin_destroy(s) pthread_mutex_destroy(s)
#endif

typedef struct {
    sha256_ctx_t hash_ctx;      /* Running SHA-256 */
    size_t entropy_bits;        /* Estimated entropy */
    stutter_spinlock_t lock;    /* Per-pool lock */
} stutter_pool_t;

typedef struct {
    stutter_pool_t pools[STUTTER_NUM_POOLS];
    unsigned long reseed_count;
    pthread_mutex_t reseed_mutex;
} stutter_accumulator_t;

void accumulator_init(stutter_accumulator_t *acc);
void accumulator_add(stutter_accumulator_t *acc, unsigned int pool,
                     const void *data, size_t len, unsigned int quality);
int  accumulator_reseed(stutter_accumulator_t *acc, unsigned char seed[32]);
int  accumulator_get_entropy_estimate(stutter_accumulator_t *acc,
                                       unsigned int pool);
void accumulator_shutdown(stutter_accumulator_t *acc);

/* ============================================================================
 * Entropy Sources (type defined in stutter.h)
 * ============================================================================ */

int entropy_init(void);
int entropy_gather(stutter_accumulator_t *acc, size_t min_bits);
void entropy_shutdown(void);

int entropy_register(const stutter_entropy_source_t *source);
int entropy_unregister(const char *name);

/* ============================================================================
 * Platform Abstraction
 * ============================================================================ */

int  platform_get_entropy(void *buf, size_t len);
void platform_secure_zero(void *buf, size_t len);
int  platform_get_time_ns(unsigned long *time_ns);

/* ============================================================================
 * Debug Support
 * ============================================================================ */

#ifdef STUTTER_DEBUG
#include <stdio.h>
#include <stdarg.h>
/*
 * Debug logging implementation.
 */
static void stutter_log_impl(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    fprintf(stderr, "[STUTTER] ");
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
    va_end(args);
}
#define STUTTER_LOG stutter_log_impl
#else
/* C89-compliant no-op: cast to void to silence warnings */
#define STUTTER_LOG (void)sizeof
#endif

#ifdef __cplusplus
}
#endif

#endif /* STUTTER_INTERNAL_H */
