/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "common/el2go_platform.h"
#include "osal.h"
#include "test_framework.h"
#include "test_suites.h"

/**
 * @defgroup test_el2go_platform_internal Internal EL2GO Platform Tests
 * @brief Unit tests for internal platform implementation details.
 *
 * Verifies that the osal_uuid() stub returns the expected status codes
 * under the Linux test build where CONFIG_HWINFO is not available.
 *
 * @{
 */

/* ========================================================================== */
/* osal_uuid() parameter validation tests                                     */
/* ========================================================================== */

/**
 * @brief osal_uuid(NULL, n, uuid_len) must return EL2GO_STATUS_INVALID_PARAMETER.
 */
static bool test_osal_uuid_null_buf(void *params)
{
    size_t uuid_len = 0U;

    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_STATUS_INVALID_PARAMETER,
                      osal_uuid(NULL, EL2GO_UUID_MAX_LEN, &uuid_len));

    return true;
}

/**
 * @brief osal_uuid(buf, 0, uuid_len) must return EL2GO_STATUS_INVALID_PARAMETER.
 */
static bool test_osal_uuid_zero_len(void *params)
{
    uint8_t buf[EL2GO_UUID_MAX_LEN];
    size_t uuid_len = 0U;

    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_STATUS_INVALID_PARAMETER, osal_uuid(buf, 0U, &uuid_len));

    return true;
}

/**
 * @brief osal_uuid(buf, n, NULL) must return EL2GO_STATUS_INVALID_PARAMETER.
 */
static bool test_osal_uuid_null_uuid_len(void *params)
{
    uint8_t buf[EL2GO_UUID_MAX_LEN];

    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_STATUS_INVALID_PARAMETER, osal_uuid(buf, sizeof(buf), NULL));

    return true;
}

/** @} */

/* ========================================================================== */
/* Suite registration                                                         */
/* ========================================================================== */

/*
 * Note: register_platform_tests() is defined in public_platform and covers
 * the public el2go_platform_get_uuid() API. The internal suite below targets
 * the osal_uuid() layer directly.  Both are registered from linux_main.c via
 * the single register_platform_tests() entry point; this file extends that
 * suite with internal tests when BUILD_INTERNAL_TESTS is defined.
 */

#if defined(BUILD_INTERNAL_TESTS)
void register_platform_internal_tests(void)
{
    TEST_SUITE_BEGIN("el2go_platform_internal");

    TEST_CASE("osal_uuid_null_buf", test_osal_uuid_null_buf, NULL);
    TEST_CASE("osal_uuid_zero_len", test_osal_uuid_zero_len, NULL);
    TEST_CASE("osal_uuid_null_uuid_len", test_osal_uuid_null_uuid_len, NULL);

    TEST_SUITE_END();
}
#endif /* BUILD_INTERNAL_TESTS */

/**
 * @brief Register internal platform tests with the test framework.
 *
 * No internal-only platform tests exist yet outside of BUILD_INTERNAL_TESTS;
 * this stub satisfies the linker requirement for the internal test executable.
 */
void register_platform_tests(void)
{
    /* No internal platform tests registered at this time. */
#if defined(BUILD_INTERNAL_TESTS)
    register_platform_internal_tests();
#endif /* BUILD_INTERNAL_TESTS */
}