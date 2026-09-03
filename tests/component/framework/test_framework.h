/*
 * Copyright 2018-2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef EL2GO_TEST_FRAMEWORK_H
#define EL2GO_TEST_FRAMEWORK_H

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

typedef enum {
    TEST_PASS = 0,
    TEST_FAIL = 1,
    TEST_SKIP = 2,
} test_result_t;

enum ct_cap {
    CT_CAP_MOCK_TRANSPORT = (1U << 0), /**< Transport replaceable with the mock (emulated only). */
    CT_CAP_REAL_TLS = (1U << 1),       /**< Real TLS connect to a reachable server. */
    CT_CAP_FLASH_FAULT = (1U << 2),    /**< Flash fault injection (emulated only). */
    CT_CAP_MCUBOOT = (1U << 3),        /**< MCUboot slot/trailer management present. */
    CT_CAP_REBOOT = (1U << 4),         /**< Target can reboot and re-enter (hardware only). */
    CT_CAP_REAL_FLASH = (1U << 5),     /**< Real/emulated flash + NVS persistence. */
};

/** @return Capability bitmask of the running target (provided by board glue). */
uint32_t ct_backend_caps(void);

/** @return true if all bits in @p caps are present on the running target. */
static inline bool ct_has_caps(uint32_t caps)
{
    return (ct_backend_caps() & caps) == caps;
}

#define TEST_LOG(fmt, ...) (void)printf("[CT] " fmt "\n", ##__VA_ARGS__)

#define TEST_LOG_FAIL(fmt, ...) \
    (void)printf("[CT] FAIL %s:%d: " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__)

/** Skip the current body unless every capability in @p caps is present. */
#define TEST_REQUIRE_CAP(caps)                                      \
    do {                                                            \
        if (!ct_has_caps(caps)) {                                   \
            TEST_LOG("SKIP: missing capability mask 0x%x", (caps)); \
            return TEST_SKIP;                                       \
        }                                                           \
    } while (0)

/** Explicitly skip the current body with a reason. */
#define TEST_SKIP_WITH(reason)     \
    do {                           \
        TEST_LOG("SKIP: " reason); \
        return TEST_SKIP;          \
    } while (0)

#define TEST_ASSERT(cond)                                 \
    do {                                                  \
        if (!(cond)) {                                    \
            TEST_LOG_FAIL("assertion failed: %s", #cond); \
            return TEST_FAIL;                             \
        }                                                 \
    } while (0)

#define TEST_ASSERT_MSG(cond, fmt, ...)        \
    do {                                       \
        if (!(cond)) {                         \
            TEST_LOG_FAIL(fmt, ##__VA_ARGS__); \
            return TEST_FAIL;                  \
        }                                      \
    } while (0)

#define TEST_ASSERT_EQ(expected, actual)                                  \
    do {                                                                  \
        long _e = (long)(expected);                                       \
        long _a = (long)(actual);                                         \
        if (_e != _a) {                                                   \
            TEST_LOG_FAIL("expected %ld, got %ld (%s)", _e, _a, #actual); \
            return TEST_FAIL;                                             \
        }                                                                 \
    } while (0)

#define TEST_ASSERT_NE(notexpected, actual)                      \
    do {                                                         \
        long _n = (long)(notexpected);                           \
        long _a = (long)(actual);                                \
        if (_n == _a) {                                          \
            TEST_LOG_FAIL("expected not %ld (%s)", _n, #actual); \
            return TEST_FAIL;                                    \
        }                                                        \
    } while (0)

#define TEST_ASSERT_TRUE(cond) TEST_ASSERT(cond)
#define TEST_ASSERT_FALSE(cond) TEST_ASSERT(!(cond))

#define TEST_ASSERT_NOT_NULL(ptr)                         \
    do {                                                  \
        if ((ptr) == NULL) {                              \
            TEST_LOG_FAIL("expected non-NULL: %s", #ptr); \
            return TEST_FAIL;                             \
        }                                                 \
    } while (0)

#define TEST_ASSERT_NULL(ptr)                         \
    do {                                              \
        if ((ptr) != NULL) {                          \
            TEST_LOG_FAIL("expected NULL: %s", #ptr); \
            return TEST_FAIL;                         \
        }                                             \
    } while (0)

#define TEST_ASSERT_STR_EQ(expected, actual)                                    \
    do {                                                                        \
        if (strcmp((expected), (actual)) != 0) {                                \
            TEST_LOG_FAIL("expected \"%s\", got \"%s\"", (expected), (actual)); \
            return TEST_FAIL;                                                   \
        }                                                                       \
    } while (0)

#define TEST_ASSERT_MEM_EQ(expected, actual, size)                            \
    do {                                                                      \
        if (memcmp((expected), (actual), (size)) != 0) {                      \
            TEST_LOG_FAIL("memory mismatch over %u bytes", (unsigned)(size)); \
            return TEST_FAIL;                                                 \
        }                                                                     \
    } while (0)

#define TEST_ASSERT_GOTO(cond, label)                     \
    do {                                                  \
        if (!(cond)) {                                    \
            TEST_LOG_FAIL("assertion failed: %s", #cond); \
            result = TEST_FAIL;                           \
            goto label;                                   \
        }                                                 \
    } while (0)

#define TEST_ASSERT_EQ_GOTO(expected, actual, label)                      \
    do {                                                                  \
        long _e = (long)(expected);                                       \
        long _a = (long)(actual);                                         \
        if (_e != _a) {                                                   \
            TEST_LOG_FAIL("expected %ld, got %ld (%s)", _e, _a, #actual); \
            result = TEST_FAIL;                                           \
            goto label;                                                   \
        }                                                                 \
    } while (0)

#define TEST_ASSERT_NE_GOTO(notexpected, actual, label)          \
    do {                                                         \
        long _n = (long)(notexpected);                           \
        long _a = (long)(actual);                                \
        if (_n == _a) {                                          \
            TEST_LOG_FAIL("expected not %ld (%s)", _n, #actual); \
            result = TEST_FAIL;                                  \
            goto label;                                          \
        }                                                        \
    } while (0)

#define TEST_ASSERT_TRUE_GOTO(cond, label) TEST_ASSERT_GOTO((cond), label)
#define TEST_ASSERT_FALSE_GOTO(cond, label) TEST_ASSERT_GOTO(!(cond), label)

#define TEST_ASSERT_NOT_NULL_GOTO(ptr, label)             \
    do {                                                  \
        if ((ptr) == NULL) {                              \
            TEST_LOG_FAIL("expected non-NULL: %s", #ptr); \
            result = TEST_FAIL;                           \
            goto label;                                   \
        }                                                 \
    } while (0)

#endif /* EL2GO_TEST_FRAMEWORK_H */
