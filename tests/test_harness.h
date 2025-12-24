/*
 * test_harness.h - Minimal test harness for Stutter CSPRNG
 *
 * Part of the Stutter CSPRNG library.
 * Copyright (C) 2024
 * SPDX-License-Identifier: LGPL-3.0-or-later
 *
 * [LLM-ARCH] Generated with human review
 */

#ifndef TEST_HARNESS_H
#define TEST_HARNESS_H

#include <stddef.h>

/* Test suite management */
void test_suite_begin(const char *name);
void test_suite_end(void);

/* Assertion functions */
void test_assert_impl(int condition, const char *expr,
                      const char *file, int line);

void test_assert_eq_bytes_impl(const unsigned char *expected,
                                const unsigned char *actual,
                                size_t len,
                                const char *expr,
                                const char *file, int line);

/* Assertion macros */
#define TEST_ASSERT(cond) \
    test_assert_impl((cond), #cond, __FILE__, __LINE__)

#define TEST_ASSERT_EQ(a, b) \
    test_assert_impl((a) == (b), #a " == " #b, __FILE__, __LINE__)

#define TEST_ASSERT_NE(a, b) \
    test_assert_impl((a) != (b), #a " != " #b, __FILE__, __LINE__)

#define TEST_ASSERT_EQ_BYTES(exp, act, len) \
    test_assert_eq_bytes_impl((exp), (act), (len), \
                               "bytes match", __FILE__, __LINE__)

#endif /* TEST_HARNESS_H */
