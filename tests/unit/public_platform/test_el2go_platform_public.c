/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <string.h>
#include <stdlib.h>

#include "common/el2go_platform.h"
#include "osal.h"
#include "test_framework.h"
#include "test_suites.h"

#include "rtp/el2go_rtp.h"

/**
 * @defgroup test_el2go_platform_public Public EL2GO Platform Tests
 * @brief Unit tests for the public el2go_platform API.
 *
 * Covers parameter validation paths for el2go_platform_get_uuid() that
 * are exercisable without hardware (no live hwinfo or secure element needed),
 * as well as lifecycle and full-buffer tests that require platform init.
 *
 * @{
 */

/**
 * @brief Suite-level context structure.
 */
typedef struct {
    el2go_rtp_ctx_t *rtp_ctx; /**< RTP context required for logging */
} suite_context_t;

/** @brief Global suite context instance. */
static suite_context_t suite_ctx = { 0 };

/**
 * @brief Suite-level setup function.
 *
 * Initialises the RTP context, which also initialises the logging
 * subsystem used by all tests in this suite.
 *
 * @param params Unused.
 */
static void suite_setup(void *params)
{
    el2go_status_t status = EL2GO_STATUS_SUCCESS;

    (void)params;

    status = el2go_rtp_init(&suite_ctx.rtp_ctx);
    if (status != EL2GO_STATUS_SUCCESS) {
        TEST_PRINT_ERROR("Failed to initialize RTP: %d", status);
        exit(1);
    }
}

/**
 * @brief Suite-level teardown function.
 *
 * Cleans up the RTP context after all tests in the suite have run.
 *
 * @param params Unused.
 */
static void suite_teardown(void *params)
{
    el2go_status_t status = EL2GO_STATUS_SUCCESS;

    (void)params;

    status = el2go_rtp_free(&suite_ctx.rtp_ctx);
    if (status != EL2GO_STATUS_SUCCESS) {
        TEST_PRINT_ERROR("Failed to cleanup RTP: %d", status);
        exit(1);
    }
}

/* ========================================================================== */
/* el2go_platform_get_uuid() parameter validation tests                       */
/* ========================================================================== */

/**
 * @brief el2go_platform_get_uuid(ctx, NULL, n, uuid_len) must return
 *        EL2GO_STATUS_INVALID_PARAMETER.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_platform_get_uuid_null_buf(void *params)
{
    size_t uuid_len = 0U;

    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_STATUS_INVALID_PARAMETER,
                      el2go_platform_get_uuid(NULL, NULL, EL2GO_UUID_MAX_LEN, &uuid_len));

    return true;
}

/**
 * @brief el2go_platform_get_uuid(ctx, buf, 0, uuid_len) must return
 *        EL2GO_STATUS_INVALID_PARAMETER.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_platform_get_uuid_zero_len(void *params)
{
    uint8_t buf[EL2GO_UUID_MAX_LEN];
    size_t uuid_len = 0U;

    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_STATUS_INVALID_PARAMETER,
                      el2go_platform_get_uuid(NULL, buf, 0U, &uuid_len));

    return true;
}

/**
 * @brief el2go_platform_get_uuid(ctx, buf, n, NULL) must return
 *        EL2GO_STATUS_INVALID_PARAMETER.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_platform_get_uuid_null_uuid_len(void *params)
{
    uint8_t buf[EL2GO_UUID_MAX_LEN];

    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_STATUS_INVALID_PARAMETER,
                      el2go_platform_get_uuid(NULL, buf, sizeof(buf), NULL));

    return true;
}

/**
 * @brief Test el2go_platform_get_uuid with a zero-length buffer.
 *
 * Verifies that providing a buffer of size zero returns
 * EL2GO_STATUS_BUFFER_TOO_SMALL.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_platform_get_uuid_buf_too_small(void *params)
{
    el2go_platform_ctx_t *platform_ctx = NULL;
    el2go_status_t status;
    uint8_t buf[EL2GO_UUID_MAX_LEN];
    size_t uuid_len = 0;
    bool test_status = true;

    (void)params;

    /* Initialize the platform so platform_ctx is valid; the buf_len == 0
     * check must fire before any UUID retrieval is attempted. */
    status = el2go_platform_init(&platform_ctx);
    if (status != EL2GO_STATUS_SUCCESS) {
        TEST_PRINT_INFO("el2go_platform_init not available - skipping");
        goto exit;
    }

    status = el2go_platform_get_uuid(platform_ctx, buf, 0U, &uuid_len);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_BUFFER_TOO_SMALL, status, exit);

exit:
    if (platform_ctx)
        el2go_platform_free(&platform_ctx);

    return test_status;
}

/**
 * @brief Test el2go_platform_get_uuid with a non-zero but too-small buffer.
 *
 * Passes buf_len = 5, which is larger than zero but smaller than any real
 * UUID size, so the implementation must return EL2GO_STATUS_BUFFER_TOO_SMALL
 * after querying the required size from the hardware.
 *
 * If the platform is not initialized or UUID retrieval is not implemented,
 * the test is skipped gracefully.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_platform_get_uuid_buf_too_small_nonzero(void *params)
{
    el2go_platform_ctx_t *platform_ctx = NULL;
    el2go_status_t status;
    uint8_t buf[5];
    size_t uuid_len = 0;
    bool test_status = true;

    (void)params;

    status = el2go_platform_init(&platform_ctx);
    if (status != EL2GO_STATUS_SUCCESS) {
        TEST_PRINT_INFO("el2go_platform_init not available - skipping");
        goto exit;
    }

    status = el2go_platform_get_uuid(platform_ctx, buf, sizeof(buf), &uuid_len);

    if (status == EL2GO_STATUS_NOT_IMPLEMENTED) {
        TEST_PRINT_INFO("el2go_platform_get_uuid not implemented - skipping");
        goto exit;
    }

    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_BUFFER_TOO_SMALL, status, exit);

exit:
    if (platform_ctx)
        el2go_platform_free(&platform_ctx);

    return test_status;
}

/**
 * @brief Test el2go_platform_get_uuid with a valid EL2GO_UUID_MAX_LEN buffer.
 *
 * Initialises the platform, calls el2go_platform_get_uuid with a stack
 * buffer of EL2GO_UUID_MAX_LEN bytes, and verifies that on success the
 * returned uuid_len is in the range (0, EL2GO_UUID_MAX_LEN].
 *
 * On platforms where UUID retrieval is not implemented the function is
 * expected to return EL2GO_STATUS_NOT_IMPLEMENTED, which is also accepted.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_platform_get_uuid_valid(void *params)
{
    el2go_platform_ctx_t *platform_ctx = NULL;
    el2go_status_t status;
    uint8_t buf[EL2GO_UUID_MAX_LEN];
    size_t uuid_len = 0;
    bool test_status = true;

    (void)params;

    status = el2go_platform_init(&platform_ctx);
    if (status != EL2GO_STATUS_SUCCESS && status != EL2GO_STATUS_NOT_IMPLEMENTED) {
        TEST_PRINT_ERROR("el2go_platform_init failed: 0x%x", status);
        test_status = false;
        goto exit;
    }

    status = el2go_platform_get_uuid(platform_ctx, buf, sizeof(buf), &uuid_len);

    if (status == EL2GO_STATUS_NOT_IMPLEMENTED) {
        TEST_PRINT_INFO("el2go_platform_get_uuid not implemented on this platform - skipping");
        goto exit;
    }

    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    TEST_ASSERT_GOTO(uuid_len > 0U, exit);
    TEST_ASSERT_GOTO(uuid_len <= EL2GO_UUID_MAX_LEN, exit);

    TEST_PRINT_INFO("UUID length: %zu bytes", uuid_len);

exit:
    if (platform_ctx)
        el2go_platform_free(&platform_ctx);

    return test_status;
}

/** @} */

/* ========================================================================== */
/* Suite registration                                                         */
/* ========================================================================== */

/**
 * @brief Register all public platform tests with the test framework.
 */
void register_platform_tests(void)
{
    TEST_SET_SUITE_SETUP(suite_setup);
    TEST_SET_SUITE_TEARDOWN(suite_teardown);

    TEST_REGISTER(test_platform_get_uuid_null_buf);
    TEST_REGISTER(test_platform_get_uuid_zero_len);
    TEST_REGISTER(test_platform_get_uuid_null_uuid_len);
    TEST_REGISTER(test_platform_get_uuid_buf_too_small);
    TEST_REGISTER(test_platform_get_uuid_buf_too_small_nonzero);
    TEST_REGISTER(test_platform_get_uuid_valid);
}

/** @} */ /* end of test_el2go_platform_public */