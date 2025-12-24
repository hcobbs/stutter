/*
 * test_main.c - Minimal test harness for Stutter CSPRNG
 *
 * Part of the Stutter CSPRNG library.
 * Copyright (C) 2024
 * SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * [LLM-ARCH] Generated with human review
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "test_harness.h"

/* Test suites declared in other files */
extern void test_sha256(void);
extern void test_aes256(void);
extern void test_generator(void);
extern void test_accumulator(void);
extern void test_thread(void);

/* Global test counters */
static int g_tests_run = 0;
static int g_tests_passed = 0;
static int g_tests_failed = 0;
static const char *g_current_suite = NULL;

void test_suite_begin(const char *name)
{
    g_current_suite = name;
    printf("\n=== %s ===\n", name);
}

void test_suite_end(void)
{
    g_current_suite = NULL;
}

void test_assert_impl(int condition, const char *expr,
                      const char *file, int line)
{
    g_tests_run++;
    if (condition) {
        g_tests_passed++;
        printf("  [PASS] %s\n", expr);
    } else {
        g_tests_failed++;
        printf("  [FAIL] %s (%s:%d)\n", expr, file, line);
    }
}

void test_assert_eq_bytes_impl(const unsigned char *expected,
                                const unsigned char *actual,
                                size_t len,
                                const char *expr,
                                const char *file, int line)
{
    g_tests_run++;
    if (memcmp(expected, actual, len) == 0) {
        g_tests_passed++;
        printf("  [PASS] %s\n", expr);
    } else {
        size_t i;
        g_tests_failed++;
        printf("  [FAIL] %s (%s:%d)\n", expr, file, line);
        printf("    Expected: ");
        for (i = 0; i < len && i < 16; i++) {
            printf("%02x", expected[i]);
        }
        if (len > 16) printf("...");
        printf("\n    Actual:   ");
        for (i = 0; i < len && i < 16; i++) {
            printf("%02x", actual[i]);
        }
        if (len > 16) printf("...");
        printf("\n");
    }
}

int main(int argc, char *argv[])
{
    int run_all = 1;

    (void)argc;
    (void)argv;

    printf("Stutter CSPRNG Test Suite\n");
    printf("=========================\n");

    if (run_all) {
        test_sha256();
        test_aes256();
        test_accumulator();
        test_generator();
        test_thread();
    }

    printf("\n=========================\n");
    printf("Results: %d passed, %d failed, %d total\n",
           g_tests_passed, g_tests_failed, g_tests_run);

    return (g_tests_failed > 0) ? 1 : 0;
}
