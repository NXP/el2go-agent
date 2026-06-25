/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <string.h>

#include "test_framework.h"
#include "test_suites.h"
#include "test_utils.h"

#include "osal.h"

#include "common/el2go_keystore.h"
#include "test_el2go_keystore_internal_common.h"

/** @defgroup test_el2go_keystore_internal_common Internal Keystore Common Tests
 * @brief Unit tests for common keystore functionality.
 *
 * Covers keystore initialization with specific IDs, type validation,
 * and proper cleanup of platform-specific contexts.
 * @{
 */

/**
 * @brief Forward declaration for keystore-specific test registration.
 *
 * This function is implemented in the keystore-specific subdirectory
 * (e.g., psa/ or sss/) and registers tests specific to that keystore type.
 */
extern void register_keystore_specific_tests(void);

/**
 * @brief Suite-level setup function.
 *
 * Called once before the first test in the suite runs.
 * Initialises the OSAL library required by all tests.
 *
 * @param params Unused.
 */
static void suite_setup(void *params)
{
    (void)params;

    osal_lib_init();
}

/**
 * @brief Helper function to cleanup a keystore instance.
 *
 * Frees all resources associated with the given keystore.
 *
 * @param keystore Pointer to the keystore to cleanup.
 * @return @c EL2GO_STATUS_SUCCESS on success, error code otherwise.
 */
el2go_status_t cleanup_keystore(el2go_keystore_t *keystore)
{
    if (!keystore)
        return EL2GO_STATUS_INVALID_POINTER;

    return el2go_keystore_free(keystore);
}

/**
 * @brief Common test for keystore initialization with a specific ID.
 *
 * Verifies that a keystore can be successfully initialized with a given ID,
 * that the keystore type matches the expected type, and that the ID
 * matches the initialization value. Also verifies proper cleanup.
 *
 * @param keystore_id The ID to use for keystore initialization.
 * @param expected_type The expected keystore type (EL2GO_KEYSTORE_SSS or EL2GO_KEYSTORE_PSA).
 * @return @c true if all assertions pass, @c false otherwise.
 */
bool common_test_keystore_init_with_id(uint32_t keystore_id, el2go_keystore_type_t expected_type)
{
    el2go_keystore_t keystore = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    bool test_status = true;

    /* Initialize keystore with specific ID */
    status = el2go_keystore_init(keystore_id, NULL, &keystore);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    /* Verify keystore type matches expected type */
    TEST_ASSERT_EQUAL_GOTO(expected_type, keystore.type, exit);

    /* Verify keystore ID matches initialization value */
    TEST_ASSERT_EQUAL_CONTINUE(keystore_id, keystore.id);

exit:
    status = cleanup_keystore(&keystore);
    TEST_ASSERT_EQUAL(EL2GO_STATUS_SUCCESS, status);
    TEST_ASSERT_PTR_EQUAL(keystore.platform_ctx, NULL);

    return test_status;
}

/**
 * @brief Register all internal keystore tests with the test framework.
 *
 * Sets the suite-level setup function and then calls the keystore-specific
 * test registration function.
 */
void register_keystore_tests(void)
{
    /* Set suite-level setup function (called once for all keystore tests) */
    TEST_SET_SUITE_SETUP(suite_setup);

    /* Register keystore-specific tests (PSA or SSS) */
    register_keystore_specific_tests();
}

/** @} */ /* end of test_el2go_keystore_internal_common */
