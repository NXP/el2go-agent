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

static bool test_datastore_plain_init_and_free(void *params)
{
    (void)params;

    return common_test_ds_init_and_free(EL2GO_DATASTORE_TYPE_PLAIN, "test_plain", 1, NULL, NULL);
}

static bool test_datastore_plain_full_transaction(void *params)
{
    (void)params;

    return common_test_ds_full_transaction(EL2GO_DATASTORE_TYPE_PLAIN, "test_plain", NULL, NULL);
}

static bool test_datastore_plain_multiple_transactions(void *params)
{
    (void)params;

    return common_test_ds_multiple_transactions(EL2GO_DATASTORE_TYPE_PLAIN, "test_plain", NULL,
                                                NULL);
}

static bool test_datastore_plain_write_at_different_offsets(void *params)
{
    (void)params;

    return common_test_ds_write_at_different_offsets(EL2GO_DATASTORE_TYPE_PLAIN, "test_plain", NULL,
                                                     NULL);
}

static bool test_datastore_plain_write_out_of_bounds(void *params)
{
    (void)params;

    return common_test_ds_write_out_of_bounds(EL2GO_DATASTORE_TYPE_PLAIN, "test_plain", NULL, NULL,
                                              EL2GO_STATUS_BUFFER_TOO_SMALL);
}

static bool test_datastore_plain_read_out_of_bounds(void *params)
{
    (void)params;

    return common_test_ds_read_out_of_bounds(EL2GO_DATASTORE_TYPE_PLAIN, "test_plain", NULL, NULL,
                                             EL2GO_STATUS_BUFFER_TOO_SMALL);
}

static bool test_datastore_plain_transaction_recovery(void *params)
{
    (void)params;

    return common_test_ds_transaction_recovery(EL2GO_DATASTORE_TYPE_PLAIN, "test_plain", NULL,
                                               NULL);
}

static bool test_datastore_plain_large_allocation(void *params)
{
    (void)params;

    return common_test_ds_large_allocation(EL2GO_DATASTORE_TYPE_PLAIN, "test_plain", NULL, NULL);
}

/* ========================================================================== */
/* Test Registration                                                          */
/* ========================================================================== */

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
}
