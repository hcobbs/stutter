/*
 * posix.c - POSIX platform abstraction layer
 *
 * Part of the Stutter CSPRNG library.
 * Copyright (C) 2024
 * SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * [LLM-ARCH] Generated with human review
 *
 * Provides platform-specific implementations for:
 * - Secure memory zeroing
 * - System entropy gathering
 * - High-resolution timing
 */

#define _POSIX_C_SOURCE 200809L

#include "../stutter_internal.h"
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <openssl/crypto.h>

/*
 * Secure memory zeroing.
 *
 * Uses OpenSSL's OPENSSL_cleanse() which is guaranteed not to be
 * optimized away by the compiler. This is the most reliable method
 * since OpenSSL uses platform-specific barriers and techniques.
 */
void platform_secure_zero(void *buf, size_t len)
{
    OPENSSL_cleanse(buf, len);
}

/*
 * Get entropy from system.
 * Tries multiple sources in order of preference.
 */
int platform_get_entropy(void *buf, size_t len)
{
    int fd;
    ssize_t result;
    size_t total;
    unsigned char *p;

    if (buf == NULL || len == 0) {
        return STUTTER_ERR_INVALID;
    }

    p = (unsigned char *)buf;
    total = 0;

    /*
     * Try /dev/urandom first (non-blocking, available everywhere)
     * On modern Linux (4.8+) this is as secure as /dev/random.
     */
    fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        while (total < len) {
            result = read(fd, p + total, len - total);
            if (result < 0) {
                if (errno == EINTR) {
                    continue;
                }
                close(fd);
                return STUTTER_ERR_PLATFORM;
            }
            if (result == 0) {
                /* Unexpected EOF */
                close(fd);
                return STUTTER_ERR_PLATFORM;
            }
            total += (size_t)result;
        }
        close(fd);
        return STUTTER_OK;
    }

    /*
     * Fallback: /dev/random (may block on some systems)
     */
    fd = open("/dev/random", O_RDONLY);
    if (fd >= 0) {
        while (total < len) {
            result = read(fd, p + total, len - total);
            if (result < 0) {
                if (errno == EINTR) {
                    continue;
                }
                close(fd);
                return STUTTER_ERR_PLATFORM;
            }
            if (result == 0) {
                close(fd);
                return STUTTER_ERR_PLATFORM;
            }
            total += (size_t)result;
        }
        close(fd);
        return STUTTER_OK;
    }

    /* No entropy source available */
    return STUTTER_ERR_PLATFORM;
}

/*
 * Get high-resolution monotonic time.
 * Used for timing jitter entropy.
 */
int platform_get_time_ns(unsigned long *time_ns)
{
    struct timespec ts;

    if (time_ns == NULL) {
        return STUTTER_ERR_INVALID;
    }

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return STUTTER_ERR_PLATFORM;
    }

    /* Combine seconds and nanoseconds */
    *time_ns = (unsigned long)ts.tv_sec * 1000000000UL +
               (unsigned long)ts.tv_nsec;

    return STUTTER_OK;
}
