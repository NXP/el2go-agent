/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <string.h>
#include <stdlib.h>

#include "builtin_macros.h"

#include "test_framework.h"
#include "test_el2go_datastore_common.h"

#include "common/el2go_datastore.h"

/* ========================================================================== */
/* Custom Datastore Implementation                                            */
/* ========================================================================== */

typedef struct {
    uint8_t *buffer;
    size_t size;
    bool transaction_active;
    uint8_t *temp_buffer;
    size_t temp_size;
} custom_datastore_ctx_t;

static el2go_status_t custom_datastore_init(void *context, el2go_datastore_validator_t validator)
{
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    custom_datastore_ctx_t *ctx = (custom_datastore_ctx_t *)context;

    (void)validator;

    if (!ctx) {
        status = EL2GO_STATUS_INVALID_PARAMETER;
        goto exit;
    }

    ctx->buffer = NULL;
    ctx->size = 0;
    ctx->transaction_active = false;
    ctx->temp_buffer = NULL;
    ctx->temp_size = 0;

exit:
    return status;
}

static el2go_status_t custom_datastore_allocate(void *context, size_t len)
{
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    custom_datastore_ctx_t *ctx = (custom_datastore_ctx_t *)context;

    if (!ctx || len == 0) {
        status = EL2GO_STATUS_INVALID_PARAMETER;
        goto exit;
    }

    if (ctx->temp_buffer) {
        free(ctx->temp_buffer);
        ctx->temp_buffer = NULL;
        ctx->temp_size = 0;
    }

    ctx->temp_buffer = (uint8_t *)calloc(len, sizeof(uint8_t));
    if (!ctx->temp_buffer) {
        status = EL2GO_STATUS_ALLOCATION_ERROR;
        goto exit;
    }

    ctx->temp_size = len;
    ctx->transaction_active = true;

exit:
    return status;
}

static el2go_status_t custom_datastore_read(void *context, void *dest, size_t offset, size_t len,
                                            size_t *bytes_read)
{
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    custom_datastore_ctx_t *ctx = (custom_datastore_ctx_t *)context;
    size_t end_offset = 0;
    size_t actual_read = 0;

    if (!ctx || !dest || len == 0 || !bytes_read) {
        status = EL2GO_STATUS_INVALID_PARAMETER;
        goto exit;
    }

    *bytes_read = 0;

    if (!ctx->buffer || ctx->size == 0) {
        status = EL2GO_STATUS_INVALID_STATE;
        goto exit;
    }

    /* Check if offset is within bounds */
    if (offset >= ctx->size) {
        status = EL2GO_STATUS_BUFFER_TOO_SMALL;
        goto exit;
    }

    if (ADD_OVERFLOW(offset, len, &end_offset)) {
        status = EL2GO_STATUS_ARITHMETIC_OVERFLOW;
        goto exit;
    }

    /* Perform partial read if requested length exceeds buffer */
    if (end_offset > ctx->size) {
        actual_read = ctx->size - offset;
        status = EL2GO_STATUS_INCOMPLETE_READ;
    } else {
        actual_read = len;
    }

    memcpy(dest, ctx->buffer + offset, actual_read);
    *bytes_read = actual_read;

exit:
    return status;
}

static el2go_status_t custom_datastore_write(void *context, const void *src, size_t offset,
                                             size_t len, size_t *bytes_written)
{
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    custom_datastore_ctx_t *ctx = (custom_datastore_ctx_t *)context;
    size_t end_offset = 0;
    size_t actual_written = 0;

    if (!ctx || !src || len == 0 || !bytes_written) {
        status = EL2GO_STATUS_INVALID_PARAMETER;
        goto exit;
    }

    *bytes_written = 0;

    if (!ctx->transaction_active || !ctx->temp_buffer) {
        status = EL2GO_STATUS_INVALID_STATE;
        goto exit;
    }

    /* Check if offset is within bounds */
    if (offset >= ctx->temp_size) {
        status = EL2GO_STATUS_BUFFER_TOO_SMALL;
        goto exit;
    }

    if (ADD_OVERFLOW(offset, len, &end_offset)) {
        status = EL2GO_STATUS_ARITHMETIC_OVERFLOW;
        goto exit;
    }

    /* Perform partial write if requested length exceeds buffer */
    if (end_offset > ctx->temp_size) {
        actual_written = ctx->temp_size - offset;
        status = EL2GO_STATUS_INCOMPLETE_WRITE;
    } else {
        actual_written = len;
    }

    memcpy(ctx->temp_buffer + offset, src, actual_written);
    *bytes_written = actual_written;

exit:
    return status;
}

static el2go_status_t custom_datastore_commit(void *context)
{
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    custom_datastore_ctx_t *ctx = (custom_datastore_ctx_t *)context;

    if (!ctx) {
        status = EL2GO_STATUS_INVALID_PARAMETER;
        goto exit;
    }

    if (!ctx->transaction_active) {
        status = EL2GO_STATUS_INVALID_STATE;
        goto exit;
    }

    if (ctx->buffer) {
        free(ctx->buffer);
        ctx->buffer = NULL;
    }

    ctx->buffer = ctx->temp_buffer;
    ctx->size = ctx->temp_size;

    ctx->temp_buffer = NULL;
    ctx->temp_size = 0;
    ctx->transaction_active = false;

exit:
    return status;
}

static el2go_status_t custom_datastore_free(void *context)
{
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    custom_datastore_ctx_t *ctx = (custom_datastore_ctx_t *)context;

    if (!ctx) {
        status = EL2GO_STATUS_INVALID_PARAMETER;
        goto exit;
    }

    if (ctx->buffer) {
        free(ctx->buffer);
        ctx->buffer = NULL;
    }

    if (ctx->temp_buffer) {
        free(ctx->temp_buffer);
        ctx->temp_buffer = NULL;
    }

    ctx->size = 0;
    ctx->temp_size = 0;
    ctx->transaction_active = false;

exit:
    return status;
}

static const el2go_datastore_ops_t custom_datastore_ops = {
    .init = custom_datastore_init,
    .allocate = custom_datastore_allocate,
    .read = custom_datastore_read,
    .write = custom_datastore_write,
    .commit = custom_datastore_commit,
    .free = custom_datastore_free,
};

/* ========================================================================== */
/* Custom Datastore Tests                                                     */
/* ========================================================================== */

static bool test_datastore_custom_init_and_free(void *params)
{
    custom_datastore_ctx_t ctx = { 0 };

    (void)params;

    return common_test_ds_init_and_free(EL2GO_DATASTORE_TYPE_CUSTOM, "test_custom", 3,
                                        &custom_datastore_ops, &ctx);
}

static bool test_datastore_custom_full_transaction(void *params)
{
    custom_datastore_ctx_t ctx = { 0 };

    (void)params;

    return common_test_ds_full_transaction(EL2GO_DATASTORE_TYPE_CUSTOM, "test_custom",
                                           &custom_datastore_ops, &ctx);
}

static bool test_datastore_custom_multiple_transactions(void *params)
{
    custom_datastore_ctx_t ctx = { 0 };

    (void)params;

    return common_test_ds_multiple_transactions(EL2GO_DATASTORE_TYPE_CUSTOM, "test_custom",
                                                &custom_datastore_ops, &ctx);
}

static bool test_datastore_custom_write_out_of_bounds(void *params)
{
    custom_datastore_ctx_t ctx = { 0 };

    (void)params;

    return common_test_ds_write_out_of_bounds(EL2GO_DATASTORE_TYPE_CUSTOM, "test_custom",
                                              &custom_datastore_ops, &ctx);
}

static bool test_datastore_custom_read_out_of_bounds(void *params)
{
    custom_datastore_ctx_t ctx = { 0 };

    (void)params;

    return common_test_ds_read_out_of_bounds(EL2GO_DATASTORE_TYPE_CUSTOM, "test_custom",
                                             &custom_datastore_ops, &ctx);
}

static bool test_datastore_custom_transaction_recovery(void *params)
{
    custom_datastore_ctx_t ctx = { 0 };

    (void)params;

    return common_test_ds_transaction_recovery(EL2GO_DATASTORE_TYPE_CUSTOM, "test_custom",
                                               &custom_datastore_ops, &ctx);
}

static bool test_datastore_custom_large_allocation(void *params)
{
    custom_datastore_ctx_t ctx = { 0 };

    (void)params;

    return common_test_ds_large_allocation(EL2GO_DATASTORE_TYPE_CUSTOM, "test_custom",
                                           &custom_datastore_ops, &ctx);
}

static bool test_datastore_custom_partial_read(void *params)
{
    custom_datastore_ctx_t ctx = { 0 };

    (void)params;

    return common_test_ds_partial_read(EL2GO_DATASTORE_TYPE_CUSTOM, "test_custom",
                                       &custom_datastore_ops, &ctx);
}

static bool test_datastore_custom_partial_write(void *params)
{
    custom_datastore_ctx_t ctx = { 0 };

    (void)params;

    return common_test_ds_partial_write(EL2GO_DATASTORE_TYPE_CUSTOM, "test_custom",
                                        &custom_datastore_ops, &ctx);
}

/* ========================================================================== */
/* Missing Operations Tests                                                   */
/* ========================================================================== */

static bool test_datastore_custom_null_ops(void *params)
{
    el2go_datastore_t datastore = { 0 };
    custom_datastore_ctx_t ctx = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    bool test_status = true;

    (void)params;

    datastore.ops = NULL;
    datastore.context = &ctx;

    status = el2go_datastore_init(3, "test_custom", EL2GO_DATASTORE_TYPE_CUSTOM, &datastore, NULL);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_INVALID_POINTER, exit);

exit:
    status = el2go_datastore_free(&datastore);
    TEST_ASSERT_EQUAL_CONTINUE(status, EL2GO_STATUS_SUCCESS);

    return test_status;
}

static bool test_datastore_custom_all_ops_null(void *params)
{
    el2go_datastore_t datastore = { 0 };
    custom_datastore_ctx_t ctx = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    bool test_status = true;
    el2go_datastore_ops_t incomplete_ops = {
        .init = NULL,
        .allocate = NULL,
        .read = NULL,
        .write = NULL,
        .commit = NULL,
        .free = NULL,
    };

    (void)params;

    datastore.ops = &incomplete_ops;
    datastore.context = &ctx;

    status = el2go_datastore_init(3, "test_custom", EL2GO_DATASTORE_TYPE_CUSTOM, &datastore, NULL);
    TEST_ASSERT_EQUAL_CONTINUE(status, EL2GO_STATUS_INVALID_POINTER);

    status = el2go_datastore_free(&datastore);
    TEST_ASSERT_EQUAL_CONTINUE(status, EL2GO_STATUS_SUCCESS);

    return test_status;
}

static bool test_datastore_custom_only_init_set(void *params)
{
    el2go_datastore_t datastore = { 0 };
    custom_datastore_ctx_t ctx = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    bool test_status = true;
    el2go_datastore_ops_t incomplete_ops = {
        .init = custom_datastore_init,
        .allocate = NULL,
        .read = NULL,
        .write = NULL,
        .commit = NULL,
        .free = NULL,
    };

    (void)params;

    datastore.ops = &incomplete_ops;
    datastore.context = &ctx;

    status = el2go_datastore_init(3, "test_custom", EL2GO_DATASTORE_TYPE_CUSTOM, &datastore, NULL);
    TEST_ASSERT_EQUAL_CONTINUE(status, EL2GO_STATUS_SUCCESS);

    status = el2go_datastore_free(&datastore);
    TEST_ASSERT_EQUAL_CONTINUE(status, EL2GO_STATUS_SUCCESS);

    return test_status;
}

static bool test_datastore_custom_partial_ops_full_cycle(void *params)
{
    el2go_datastore_t datastore = { 0 };
    custom_datastore_ctx_t ctx = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    uint8_t write_data[32] = { 1, 2, 3, 4, 5 };
    uint8_t read_data[32] = { 0 };
    size_t bytes_written = 0;
    size_t bytes_read = 0;
    bool test_status = true;
    el2go_datastore_ops_t incomplete_ops = {
        .init = custom_datastore_init,
        .allocate = custom_datastore_allocate,
        .read = NULL,
        .write = custom_datastore_write,
        .commit = custom_datastore_commit,
        .free = NULL,
    };

    (void)params;

    datastore.ops = &incomplete_ops;
    datastore.context = &ctx;

    status = el2go_datastore_init(3, "test_custom", EL2GO_DATASTORE_TYPE_CUSTOM, &datastore, NULL);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    status = el2go_datastore_allocate(&datastore, sizeof(write_data));
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    status = el2go_datastore_write(&datastore, write_data, 0, sizeof(write_data), &bytes_written);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);
    TEST_ASSERT_EQUAL_GOTO(bytes_written, sizeof(write_data), exit);

    status = el2go_datastore_commit(&datastore);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    status = el2go_datastore_read(&datastore, read_data, 0, sizeof(read_data), &bytes_read);
    TEST_ASSERT_EQUAL_CONTINUE(status, EL2GO_STATUS_INVALID_PARAMETER);

exit:
    status = el2go_datastore_free(&datastore);
    TEST_ASSERT_EQUAL_CONTINUE(status, EL2GO_STATUS_SUCCESS);

    return test_status;
}

/* ========================================================================== */
/* Test Registration                                                          */
/* ========================================================================== */

void register_datastore_custom_tests(void)
{
    /* Initialization tests */
    TEST_REGISTER(test_datastore_custom_init_and_free);

    /* Transaction workflow tests */
    TEST_REGISTER(test_datastore_custom_full_transaction);
    TEST_REGISTER(test_datastore_custom_multiple_transactions);

    /* Edge case tests */
    TEST_REGISTER(test_datastore_custom_write_out_of_bounds);
    TEST_REGISTER(test_datastore_custom_read_out_of_bounds);
    TEST_REGISTER(test_datastore_custom_transaction_recovery);
    TEST_REGISTER(test_datastore_custom_large_allocation);

    /* Partial read/write tests */
    TEST_REGISTER(test_datastore_custom_partial_read);
    TEST_REGISTER(test_datastore_custom_partial_write);

    /* Missing operations tests */
    TEST_REGISTER(test_datastore_custom_null_ops);
    TEST_REGISTER(test_datastore_custom_all_ops_null);
    TEST_REGISTER(test_datastore_custom_only_init_set);
    TEST_REGISTER(test_datastore_custom_partial_ops_full_cycle);
}
