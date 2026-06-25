/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <string.h>
#include <stdlib.h>

#include "test_framework.h"
#include "test_suites.h"

#include "rtp/el2go_rtp.h"
#include "common/el2go_keystore.h"

/** @defgroup test_el2go_keystore_public Public Keystore API Tests
 * @brief Unit tests for the public keystore API.
 *
 * Covers parameter validation for keystore initialization, cleanup,
 * session management, and request handling, as well as basic lifecycle
 * operations.
 * @{
 */

/**
 * @brief Suite-level context structure.
 *
 * Holds shared resources used across multiple tests in the suite.
 */
typedef struct {
    el2go_rtp_ctx_t *rtp_ctx; /**< RTP context for keystore operations */
} suite_context_t;

/** @brief Global suite context instance. */
static suite_context_t suite_ctx = { 0 };

/**
 * @brief Suite-level setup function.
 *
 * Called once before the first test in the suite runs.
 * Initialises the RTP context required by keystore operations.
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
 * Called once after all tests in the suite have completed.
 * Cleans up the RTP context.
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

/**
 * @brief Test keystore initialization with NULL parameters.
 *
 * Verifies that passing @c NULL for the keystore output parameter returns
 * an invalid parameter error.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_keystore_init_null_parameters(void *params)
{
    el2go_keystore_t keystore = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    bool test_status = true;

    (void)params;

    status = el2go_keystore_init(1, NULL, NULL);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_INVALID_PARAMETER, status, exit);

exit:
    status = el2go_keystore_free(&keystore);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_SUCCESS, status);

    return test_status;
}

/**
 * @brief Test keystore free with NULL pointer.
 *
 * Verifies that passing @c NULL to the free function returns an invalid
 * parameter error.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_keystore_free_null_pointer(void *params)
{
    el2go_status_t status = EL2GO_STATUS_SUCCESS;

    (void)params;

    status = el2go_keystore_free(NULL);
    TEST_ASSERT_EQUAL(EL2GO_STATUS_INVALID_PARAMETER, status);

    return true;
}

/**
 * @brief Test keystore open session with NULL pointer.
 *
 * Verifies that passing @c NULL to the open session function returns an
 * invalid parameter error.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_keystore_open_session_null_pointer(void *params)
{
    el2go_status_t status = EL2GO_STATUS_SUCCESS;

    (void)params;

    status = el2go_keystore_open_session(NULL);
    TEST_ASSERT_EQUAL(EL2GO_STATUS_INVALID_PARAMETER, status);

    return true;
}

/**
 * @brief Test keystore close session with NULL pointer.
 *
 * Verifies that passing @c NULL to the close session function returns an
 * invalid parameter error.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_keystore_close_session_null_pointer(void *params)
{
    el2go_status_t status = EL2GO_STATUS_SUCCESS;

    (void)params;

    status = el2go_keystore_close_session(NULL);
    TEST_ASSERT_EQUAL(EL2GO_STATUS_INVALID_PARAMETER, status);

    return true;
}

/**
 * @brief Test keystore handle request with NULL keystore.
 *
 * Verifies that passing @c NULL for the keystore parameter returns an
 * invalid parameter error.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_keystore_handle_request_null_keystore(void *params)
{
    el2go_status_t status = EL2GO_STATUS_SUCCESS;

    (void)params;

    status = el2go_keystore_handle_request(NULL, NULL, NULL, NULL);
    TEST_ASSERT_EQUAL(EL2GO_STATUS_INVALID_PARAMETER, status);

    return true;
}

/**
 * @brief Test basic keystore lifecycle operations.
 *
 * Verifies that a keystore can be successfully initialized, a session can
 * be opened and closed, and the keystore can be properly freed.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_keystore_basic_lifecycle(void *params)
{
    el2go_keystore_t keystore = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    bool test_status = true;

    (void)params;

    status = el2go_keystore_init(1, NULL, &keystore);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    status = el2go_keystore_open_session(&keystore);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    status = el2go_keystore_close_session(&keystore);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_SUCCESS, status);

exit:
    status = el2go_keystore_free(&keystore);
    TEST_ASSERT_EQUAL(EL2GO_STATUS_SUCCESS, status);

    return test_status;
}

/**
 * @brief Register all public keystore tests with the test framework.
 *
 * Sets the suite-level setup and teardown functions and registers every
 * test function in the order they should be executed.
 */
void register_keystore_tests(void)
{
    /* Set suite-level setup and teardown */
    TEST_SET_SUITE_SETUP(suite_setup);
    TEST_SET_SUITE_TEARDOWN(suite_teardown);

    /* Parameter validation tests */
    TEST_REGISTER(test_keystore_init_null_parameters);
    TEST_REGISTER(test_keystore_free_null_pointer);
    TEST_REGISTER(test_keystore_open_session_null_pointer);
    TEST_REGISTER(test_keystore_close_session_null_pointer);
    TEST_REGISTER(test_keystore_handle_request_null_keystore);

    /* Basic lifecycle tests */
    TEST_REGISTER(test_keystore_basic_lifecycle);
}

/** @} */ /* end of test_el2go_keystore_public */
