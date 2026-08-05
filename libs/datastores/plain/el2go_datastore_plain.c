/*
 * Copyright 2018-2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <string.h>

#include "builtin_macros.h"
#include "osal.h"
#include "debug.h"

#include "el2go_datastore_plain.h"
#include "datastore_priv.h"

#define BUFFER_NUMBER 2U

/* Internal buffer slot: tracks both the allocation and how many bytes have been written. */
typedef struct {
    uint8_t *data;     /* Pointer to allocated memory */
    size_t len;        /* Total allocated length */
    size_t bytes_used; /* High-water mark of bytes written */
} plain_slot_t;

typedef struct el2go_datastore_plain_context {
    plain_slot_t slots[BUFFER_NUMBER];
    unsigned int idx_read;
    unsigned int idx_write;
} el2go_datastore_plain_context_t;

static el2go_status_t el2go_datastore_plain_init(void *context,
                                                 el2go_datastore_validator_t validator);
static el2go_status_t el2go_datastore_plain_allocate(void *context, size_t len);
static el2go_status_t el2go_datastore_plain_read(void *context, void *dest, size_t offset,
                                                 size_t len, size_t *bytes_read);
static el2go_status_t el2go_datastore_plain_write(void *context, const void *src, size_t offset,
                                                  size_t len, size_t *bytes_written);
static el2go_status_t el2go_datastore_plain_commit(void *context);
static el2go_status_t el2go_datastore_plain_get_size(void *context, size_t *size);
static el2go_status_t el2go_datastore_plain_free(void *context);
static const el2go_datastore_ops_t plain_ops = {
    .init = el2go_datastore_plain_init,
    .allocate = el2go_datastore_plain_allocate,
    .read = el2go_datastore_plain_read,
    .write = el2go_datastore_plain_write,
    .commit = el2go_datastore_plain_commit,
    .get_size = el2go_datastore_plain_get_size,
    .free = el2go_datastore_plain_free,
};

el2go_status_t el2go_datastore_plain_create(el2go_datastore_t *datastore, const char *basename)
{
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    el2go_datastore_plain_context_t *ctx = NULL;

    EL2GO_DBG_TRACE_FUNCTION_CALL;

    (void)basename;

    if (!datastore) {
        status = EL2GO_STATUS_INVALID_PARAMETER;
        goto exit;
    }

    datastore->context = NULL;
    datastore->ops = NULL;

    ctx =
        (el2go_datastore_plain_context_t *)osal_calloc(1, sizeof(el2go_datastore_plain_context_t));
    if (!ctx) {
        EL2GO_DBG_PRINTF(ERROR, "Allocation error\n");
        status = EL2GO_STATUS_ALLOCATION_ERROR;
        goto exit;
    }

    datastore->ops = &plain_ops;
    datastore->context = ctx;

exit:
    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}

static el2go_status_t el2go_datastore_plain_init(void *context,
                                                 el2go_datastore_validator_t validator)
{
    el2go_status_t status = EL2GO_STATUS_SUCCESS;

    EL2GO_DBG_TRACE_FUNCTION_CALL;

    (void)validator;

    if (!context)
        status = EL2GO_STATUS_INVALID_PARAMETER;

    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}

static el2go_status_t el2go_datastore_plain_allocate(void *context, size_t len)
{
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    el2go_datastore_plain_context_t *ctx = (el2go_datastore_plain_context_t *)context;

    EL2GO_DBG_TRACE_FUNCTION_CALL;

    if (!ctx || len == 0) {
        status = EL2GO_STATUS_INVALID_PARAMETER;
        goto exit;
    }

    if (ctx->idx_read >= BUFFER_NUMBER || ctx->idx_write >= BUFFER_NUMBER) {
        EL2GO_DBG_PRINTF(ERROR, "Invalid buffer index\n");
        status = EL2GO_STATUS_INVALID_STATE;
        goto exit;
    }

    /**
	 * If currently read and write indices are different, there is a
	 * transaction ongoing already. In that case recover by terminating
	 * (without commit) the ongoing transaction and starting a fresh one.
	 */
    if (ctx->idx_read != ctx->idx_write) {
        if (ctx->slots[ctx->idx_write].data) {
            osal_free(ctx->slots[ctx->idx_write].data);
            ctx->slots[ctx->idx_write].data = NULL;
        }
        ctx->slots[ctx->idx_write].len = 0;
        ctx->slots[ctx->idx_write].bytes_used = 0;
    } else {
        ctx->idx_write = (ctx->idx_write + 1) & 0x01;
    }

    if (ctx->idx_write >= BUFFER_NUMBER) {
        EL2GO_DBG_PRINTF(ERROR, "Overflow in write index\n");
        status = EL2GO_STATUS_INVALID_STATE;
        goto exit;
    }

    ctx->slots[ctx->idx_write].data = (uint8_t *)osal_calloc(len, sizeof(uint8_t));
    if (!ctx->slots[ctx->idx_write].data) {
        EL2GO_DBG_PRINTF(ERROR, "Allocation error\n");
        status = EL2GO_STATUS_ALLOCATION_ERROR;
        goto exit;
    }

    ctx->slots[ctx->idx_write].len = len;
    ctx->slots[ctx->idx_write].bytes_used = 0;

exit:
    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}

static el2go_status_t el2go_datastore_plain_write(void *context, const void *src, size_t offset,
                                                  size_t len, size_t *bytes_written)
{
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    el2go_datastore_plain_context_t *ctx = (el2go_datastore_plain_context_t *)context;
    uint8_t *write_buffer = NULL;
    size_t write_buffer_size = 0;
    size_t end_offset = 0;
    size_t actual_written = 0;

    EL2GO_DBG_TRACE_FUNCTION_CALL;

    if (!ctx || !src || len == 0 || !bytes_written) {
        status = EL2GO_STATUS_INVALID_PARAMETER;
        goto exit;
    }

    *bytes_written = 0;

    if (ctx->idx_write >= BUFFER_NUMBER) {
        EL2GO_DBG_PRINTF(ERROR, "Overflow in write index\n");
        status = EL2GO_STATUS_INVALID_STATE;
        goto exit;
    }

    write_buffer = ctx->slots[ctx->idx_write].data;
    if (!write_buffer) {
        EL2GO_DBG_PRINTF(ERROR, "Write buffer is NULL\n");
        status = EL2GO_STATUS_INVALID_POINTER;
        goto exit;
    }

    write_buffer_size = ctx->slots[ctx->idx_write].len;

    /* Check if offset is within bounds */
    if (offset >= write_buffer_size) {
        EL2GO_DBG_PRINTF(ERROR, "Offset out of bounds: offset: %zu, buffer_size: %zu\n", offset,
                         write_buffer_size);
        status = EL2GO_STATUS_BUFFER_TOO_SMALL;
        goto exit;
    }

    if (ADD_OVERFLOW(offset, len, &end_offset)) {
        EL2GO_DBG_PRINTF(ERROR, "Overflow in offset calculation\n");
        status = EL2GO_STATUS_ARITHMETIC_OVERFLOW;
        goto exit;
    }

    /* Perform partial write if requested length exceeds buffer */
    if (end_offset > write_buffer_size) {
        actual_written = write_buffer_size - offset;
        EL2GO_DBG_PRINTF(DEBUG, "Incomplete write: requested: %zu, available: %zu\n", len,
                         actual_written);
        status = EL2GO_STATUS_INCOMPLETE_WRITE;
    } else {
        actual_written = len;
    }

    memcpy(write_buffer + offset, src, actual_written);
    *bytes_written = actual_written;

    /* Update high-water mark of bytes written for this slot. */
    {
        size_t new_end = offset + actual_written;
        if (new_end > ctx->slots[ctx->idx_write].bytes_used)
            ctx->slots[ctx->idx_write].bytes_used = new_end;
    }

exit:
    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}

static el2go_status_t el2go_datastore_plain_read(void *context, void *dest, size_t offset,
                                                 size_t len, size_t *bytes_read)
{
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    el2go_datastore_plain_context_t *ctx = (el2go_datastore_plain_context_t *)context;
    uint8_t *read_buffer = NULL;
    size_t read_buffer_size = 0;
    size_t end_offset = 0;
    size_t actual_read = 0;

    EL2GO_DBG_TRACE_FUNCTION_CALL;

    if (!ctx || !dest || len == 0 || !bytes_read) {
        status = EL2GO_STATUS_INVALID_PARAMETER;
        goto exit;
    }

    *bytes_read = 0;

    if (ctx->idx_read >= BUFFER_NUMBER) {
        EL2GO_DBG_PRINTF(ERROR, "Overflow in read index\n");
        status = EL2GO_STATUS_INVALID_STATE;
        goto exit;
    }

    read_buffer = ctx->slots[ctx->idx_read].data;
    if (!read_buffer) {
        EL2GO_DBG_PRINTF(ERROR, "Read buffer is NULL\n");
        status = EL2GO_STATUS_INVALID_POINTER;
        goto exit;
    }

    /* Use bytes actually written, not the allocation size. */
    read_buffer_size = ctx->slots[ctx->idx_read].bytes_used;

    /* Check if offset is within bounds */
    if (offset >= read_buffer_size) {
        EL2GO_DBG_PRINTF(ERROR, "Offset out of bounds: offset: %zu, buffer_size: %zu\n", offset,
                         read_buffer_size);
        status = EL2GO_STATUS_BUFFER_TOO_SMALL;
        goto exit;
    }

    if (ADD_OVERFLOW(offset, len, &end_offset)) {
        EL2GO_DBG_PRINTF(ERROR, "Overflow in offset calculation\n");
        status = EL2GO_STATUS_ARITHMETIC_OVERFLOW;
        goto exit;
    }

    /* Perform partial read if requested length exceeds buffer */
    if (end_offset > read_buffer_size) {
        actual_read = read_buffer_size - offset;
        EL2GO_DBG_PRINTF(DEBUG, "Incomplete read: requested: %zu, available: %zu\n", len,
                         actual_read);
        status = EL2GO_STATUS_INCOMPLETE_READ;
    } else {
        actual_read = len;
    }

    memcpy(dest, read_buffer + offset, actual_read);
    *bytes_read = actual_read;

exit:
    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}

static el2go_status_t el2go_datastore_plain_commit(void *context)
{
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    el2go_datastore_plain_context_t *ctx = (el2go_datastore_plain_context_t *)context;

    EL2GO_DBG_TRACE_FUNCTION_CALL;

    if (!ctx) {
        status = EL2GO_STATUS_INVALID_PARAMETER;
        goto exit;
    }

    if (ctx->idx_read == ctx->idx_write) {
        EL2GO_DBG_PRINTF(ERROR, "No transaction in progress\n");
        status = EL2GO_STATUS_INVALID_STATE;
        goto exit;
    }

    /* Free the current read buffer */
    if (ctx->slots[ctx->idx_read].data) {
        osal_free(ctx->slots[ctx->idx_read].data);
        ctx->slots[ctx->idx_read].data = NULL;
    }
    ctx->slots[ctx->idx_read].len = 0;
    ctx->slots[ctx->idx_read].bytes_used = 0;

    /* Make reads point to the write buffer */
    ctx->idx_read = ctx->idx_write;

exit:
    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}

static el2go_status_t el2go_datastore_plain_get_size(void *context, size_t *size)
{
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    el2go_datastore_plain_context_t *ctx = (el2go_datastore_plain_context_t *)context;

    EL2GO_DBG_TRACE_FUNCTION_CALL;

    if (!ctx || !size) {
        status = EL2GO_STATUS_INVALID_PARAMETER;
        goto exit;
    }

    if (ctx->idx_read >= BUFFER_NUMBER) {
        EL2GO_DBG_PRINTF(ERROR, "Overflow in read index\n");
        status = EL2GO_STATUS_INVALID_STATE;
        goto exit;
    }

    *size = ctx->slots[ctx->idx_read].bytes_used;

exit:
    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}

static el2go_status_t el2go_datastore_plain_free(void *context)
{
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    el2go_datastore_plain_context_t *ctx = (el2go_datastore_plain_context_t *)context;
    unsigned int i = 0;

    EL2GO_DBG_TRACE_FUNCTION_CALL;

    if (!ctx)
        goto exit;

    for (; i < BUFFER_NUMBER; i++) {
        if (ctx->slots[i].data) {
            osal_free(ctx->slots[i].data);
            ctx->slots[i].data = NULL;
        }
        ctx->slots[i].len = 0;
        ctx->slots[i].bytes_used = 0;
    }

    ctx->idx_read = 0;
    ctx->idx_write = 0;

    osal_free(ctx);

exit:
    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}
