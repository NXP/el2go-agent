/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <string.h>
#include <stdlib.h>

#include "test_framework.h"
#include "test_el2go_datastore_common.h"

#include "common/el2go_datastore.h"

/* ========================================================================== */
/* Plain Datastore Tests                                                   */
/* ========================================================================== */

/**
 * @brief Verify that a plain datastore can be initialized and freed without errors.
 *
 * Delegates to the common initialization and free test using
 * EL2GO_DATASTORE_TYPE_PLAIN with no custom ops or context.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_datastore_plain_init_and_free(void *params)
{
    (void)params;

    return common_test_ds_init_and_free(EL2GO_DATASTORE_TYPE_PLAIN, "test_plain", 1, NULL, NULL);
}

/**
 * @brief Verify that a plain datastore can perform a complete allocate/write/commit/read cycle.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_datastore_plain_full_transaction(void *params)
{
    (void)params;

    return common_test_ds_full_transaction(EL2GO_DATASTORE_TYPE_PLAIN, "test_plain", NULL, NULL);
}

/**
 * @brief Verify that a plain datastore handles multiple sequential transactions correctly.
 *
 * Each transaction overwrites the previous committed data; the last committed
 * content must be readable after the final commit.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_datastore_plain_multiple_transactions(void *params)
{
    (void)params;

    return common_test_ds_multiple_transactions(EL2GO_DATASTORE_TYPE_PLAIN, "test_plain", NULL,
                                                NULL);
}

/**
 * @brief Verify that a plain datastore accepts writes at non-zero offsets within the buffer.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_datastore_plain_write_at_different_offsets(void *params)
{
    (void)params;

    return common_test_ds_write_at_different_offsets(EL2GO_DATASTORE_TYPE_PLAIN, "test_plain", NULL,
                                                     NULL);
}

/**
 * @brief Verify that writing beyond the allocated size returns the expected error.
 *
 * A write request whose (offset + length) exceeds the allocation must return
 * EL2GO_STATUS_BUFFER_TOO_SMALL or EL2GO_STATUS_INCOMPLETE_WRITE.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_datastore_plain_write_out_of_bounds(void *params)
{
    (void)params;

    return common_test_ds_write_out_of_bounds(EL2GO_DATASTORE_TYPE_PLAIN, "test_plain", NULL, NULL);
}

/**
 * @brief Verify that reading beyond the committed data size returns the
 *        expected error status.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_datastore_plain_read_out_of_bounds(void *params)
{
    (void)params;

    return common_test_ds_read_out_of_bounds(EL2GO_DATASTORE_TYPE_PLAIN, "test_plain", NULL, NULL);
}

/**
 * @brief Verify that a plain datastore recovers correctly after an aborted transaction.
 *
 * An allocation followed by a new allocation without a commit must discard the
 * first pending buffer and allow the second transaction to proceed normally.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_datastore_plain_transaction_recovery(void *params)
{
    (void)params;

    return common_test_ds_transaction_recovery(EL2GO_DATASTORE_TYPE_PLAIN, "test_plain", NULL,
                                               NULL);
}

/**
 * @brief Verify that a plain datastore can handle a large allocation without errors.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_datastore_plain_large_allocation(void *params)
{
    (void)params;

    return common_test_ds_large_allocation(EL2GO_DATASTORE_TYPE_PLAIN, "test_plain", NULL, NULL);
}

/**
 * @brief Verify that a partial read returns EL2GO_STATUS_INCOMPLETE_READ
 *        and reports the number of bytes actually available.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_datastore_plain_partial_read(void *params)
{
    (void)params;

    return common_test_ds_partial_read(EL2GO_DATASTORE_TYPE_PLAIN, "test_plain", NULL, NULL);
}

/**
 * @brief Verify that a partial write returns EL2GO_STATUS_INCOMPLETE_WRITE and
 *        the number of bytes actually written when the source exceeds the allocation.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_datastore_plain_partial_write(void *params)
{
    (void)params;

    return common_test_ds_partial_write(EL2GO_DATASTORE_TYPE_PLAIN, "test_plain", NULL, NULL);
}

/* ========================================================================== */
/* Test Registration                                                          */
/* ========================================================================== */

/**
 * @brief Register all plain datastore tests with the test framework.
 */
void register_datastore_plain_tests(void)
{
    /* Initialization tests */
    TEST_REGISTER(test_datastore_plain_init_and_free);

    /* Transaction workflow tests */
    TEST_REGISTER(test_datastore_plain_full_transaction);
    TEST_REGISTER(test_datastore_plain_multiple_transactions);
    TEST_REGISTER(test_datastore_plain_write_at_different_offsets);

    /* Edge case tests */
    TEST_REGISTER(test_datastore_plain_write_out_of_bounds);
    TEST_REGISTER(test_datastore_plain_read_out_of_bounds);
    TEST_REGISTER(test_datastore_plain_transaction_recovery);
    TEST_REGISTER(test_datastore_plain_large_allocation);

    /* Partial read/write tests */
    TEST_REGISTER(test_datastore_plain_partial_read);
    TEST_REGISTER(test_datastore_plain_partial_write);
}
