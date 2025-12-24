/*
 * basic_usage.c - Example usage of Stutter CSPRNG
 *
 * Part of the Stutter CSPRNG library.
 * Copyright (C) 2024
 * SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * [LLM-ARCH] Generated with human review
 *
 * Build: make example
 * Run:   ./bin/example
 */

#include <stdio.h>
#include <stdlib.h>
#include "stutter.h"

static void print_hex(const unsigned char *buf, size_t len)
{
    size_t i;
    for (i = 0; i < len; i++) {
        printf("%02x", buf[i]);
        if ((i + 1) % 16 == 0) {
            printf("\n");
        } else if ((i + 1) % 4 == 0) {
            printf(" ");
        }
    }
    if (len % 16 != 0) {
        printf("\n");
    }
}

int main(void)
{
    unsigned char random_bytes[64];
    int result;
    int reseed_count;

    printf("Stutter CSPRNG Example\n");
    printf("======================\n\n");

    /* Initialize the library */
    printf("Initializing...\n");
    result = stutter_init();
    if (result != STUTTER_OK) {
        fprintf(stderr, "Failed to initialize: %d\n", result);
        return 1;
    }
    printf("Initialization complete.\n\n");

    /* Check seeded status */
    printf("Seeded: %s\n", stutter_is_seeded() ? "yes" : "no");
    reseed_count = stutter_get_reseed_count();
    printf("Initial reseed count: %d\n\n", reseed_count);

    /* Generate some random bytes */
    printf("Generating 64 random bytes:\n");
    result = stutter_rand(random_bytes, sizeof(random_bytes));
    if (result != STUTTER_OK) {
        fprintf(stderr, "Failed to generate random bytes: %d\n", result);
        stutter_shutdown();
        return 1;
    }
    print_hex(random_bytes, sizeof(random_bytes));
    printf("\n");

    /* Force a reseed */
    printf("Forcing reseed...\n");
    result = stutter_reseed();
    if (result != STUTTER_OK) {
        fprintf(stderr, "Failed to reseed: %d\n", result);
        stutter_shutdown();
        return 1;
    }
    reseed_count = stutter_get_reseed_count();
    printf("Reseed count after forced reseed: %d\n\n", reseed_count);

    /* Generate more random bytes after reseed */
    printf("Generating another 64 random bytes after reseed:\n");
    result = stutter_rand(random_bytes, sizeof(random_bytes));
    if (result != STUTTER_OK) {
        fprintf(stderr, "Failed to generate random bytes: %d\n", result);
        stutter_shutdown();
        return 1;
    }
    print_hex(random_bytes, sizeof(random_bytes));
    printf("\n");

    /* Add custom entropy */
    printf("Adding custom entropy...\n");
    {
        const char *custom_entropy = "This is application-specific entropy!";
        result = stutter_add_entropy(0, custom_entropy, 38);
        if (result != STUTTER_OK) {
            fprintf(stderr, "Failed to add entropy: %d\n", result);
        } else {
            printf("Custom entropy added to pool 0.\n\n");
        }
    }

    /* Clean shutdown */
    printf("Shutting down...\n");
    stutter_shutdown();
    printf("Done.\n");

    return 0;
}
