// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright 2018-2026 NXP
 */

#include <string.h>
#include <stdbool.h>

#include "builtin_macros.h"
#include "osal.h"
#include "debug.h"

#include "el2go_datastore_fs.h"

#define FILE_POINTER_NUMBER 2U
#define MAX_UINT_DECIMAL_DIGITS 20U

typedef struct el2go_datastore_fs_context {
	char *filenames[FILE_POINTER_NUMBER];
	osal_file_t *fp[FILE_POINTER_NUMBER];
	unsigned int idx_read;
	unsigned int idx_write;
} el2go_datastore_fs_context_t;

static el2go_status_t
el2go_datastore_fs_init(void *context, el2go_datastore_validator_t validator);
static el2go_status_t el2go_datastore_fs_allocate(void *context, size_t len);
static el2go_status_t el2go_datastore_fs_read(void *context, void *dest,
					      size_t offset, size_t len);
static el2go_status_t el2go_datastore_fs_write(void *context, const void *src,
					       size_t offset, size_t len);
static el2go_status_t el2go_datastore_fs_commit(void *context);
static el2go_status_t el2go_datastore_fs_free(void *context);

static const el2go_datastore_ops_t fs_ops = {
	.init = el2go_datastore_fs_init,
	.allocate = el2go_datastore_fs_allocate,
	.read = el2go_datastore_fs_read,
	.write = el2go_datastore_fs_write,
	.commit = el2go_datastore_fs_commit,
	.free = el2go_datastore_fs_free,
};

static el2go_status_t open_file(osal_file_t **fp, const char *filename,
				const char *mode)
{
	el2go_status_t status = EL2GO_STATUS_SUCCESS;

	EL2GO_DBG_TRACE_FUNCTION_CALL;

	if (!fp || !filename || !mode) {
		status = EL2GO_STATUS_INVALID_PARAMETER;
		goto exit;
	}

	if (*fp) {
		osal_fclose(*fp);
		*fp = NULL;
	}

	*fp = osal_fopen(filename, mode);
	if (!*fp) {
		EL2GO_DBG_PRINTF(ERROR, "Failed to open file: %s (mode: %s)\n",
				 filename, mode);
		status = EL2GO_STATUS_FILE_OPEN_ERROR;
		goto exit;
	}

exit:
	EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

el2go_status_t el2go_datastore_fs_create(el2go_datastore_t *datastore,
					 const char *basename)
{
	el2go_status_t status = EL2GO_STATUS_SUCCESS;
	el2go_datastore_fs_context_t *ctx = NULL;
	size_t basename_len = 0;
	size_t filename_size = 0;
	unsigned int i = 0;
	int ret = 0;

	EL2GO_DBG_TRACE_FUNCTION_CALL;

	if (!datastore || !basename) {
		status = EL2GO_STATUS_INVALID_PARAMETER;
		goto exit;
	}

	datastore->context = NULL;
	datastore->ops = NULL;

	ctx = (el2go_datastore_fs_context_t *)
		osal_calloc(/* force clang format */
			    1, sizeof(el2go_datastore_fs_context_t));
	if (!ctx) {
		EL2GO_DBG_PRINTF(ERROR, "Allocation error for context\n");
		status = EL2GO_STATUS_ALLOCATION_ERROR;
		goto exit;
	}

	/* Build filenames */
	basename_len = strlen(basename);
	/* basename + '.' + digits + '\0' */
	if (ADD_OVERFLOW(basename_len, MAX_UINT_DECIMAL_DIGITS + 2,
			 &filename_size)) {
		EL2GO_DBG_PRINTF(ERROR,
				 "Overflow in filename size calculation\n");
		status = EL2GO_STATUS_ARITHMETIC_OVERFLOW;
		goto cleanup;
	}

	for (; i < FILE_POINTER_NUMBER; i++) {
		ctx->filenames[i] =
			(char *)osal_calloc(filename_size, sizeof(char));
		if (!ctx->filenames[i]) {
			EL2GO_DBG_PRINTF(/* force clang format */
					 ERROR,
					 "Allocation error for filename %u\n",
					 i);
			status = EL2GO_STATUS_ALLOCATION_ERROR;
			goto cleanup;
		}

		ret = osal_snprintf(ctx->filenames[i], filename_size, "%s.%u",
				    basename, i);
		if (ret < 0) {
			EL2GO_DBG_PRINTF(ERROR,
					 "Failed to format filename %u\n", i);
			status = EL2GO_STATUS_BUFFER_TOO_SMALL;
			goto cleanup;
		}
	}

	datastore->ops = &fs_ops;
	datastore->context = ctx;
	goto exit;

cleanup:
	for (i = 0; i < FILE_POINTER_NUMBER; i++) {
		if (ctx->filenames[i]) {
			osal_free(ctx->filenames[i]);
			ctx->filenames[i] = NULL;
		}
	}
	osal_free(ctx);

exit:
	EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static el2go_status_t
el2go_datastore_fs_init(void *context, el2go_datastore_validator_t validator)
{
	el2go_status_t status = EL2GO_STATUS_SUCCESS;
	el2go_datastore_fs_context_t *ctx =
		(el2go_datastore_fs_context_t *)context;
	el2go_datastore_t validating_datastore = { 0 };
	bool valid[FILE_POINTER_NUMBER] = { false };
	unsigned int i = 0;
	unsigned int valid_file_idx = 0;

	EL2GO_DBG_TRACE_FUNCTION_CALL;

	if (!ctx) {
		status = EL2GO_STATUS_INVALID_PARAMETER;
		goto exit;
	}

	/* Verify filenames were created */
	for (; i < FILE_POINTER_NUMBER; i++) {
		if (!ctx->filenames[i]) {
			EL2GO_DBG_PRINTF(ERROR, "Filename %u not initialized\n",
					 i);
			status = EL2GO_STATUS_INVALID_PARAMETER;
			goto exit;
		}
	}

	ctx->idx_read = 0;
	ctx->idx_write = 0;

	validating_datastore.context = ctx;
	validating_datastore.ops = &fs_ops;

	/* Try to open files and check which ones exist/are valid */
	for (i = 0; i < FILE_POINTER_NUMBER; i++) {
		status = open_file(&ctx->fp[i], ctx->filenames[i], "r+b");
		if (status == EL2GO_STATUS_SUCCESS && validator) {
			ctx->idx_read = i;
			status = validator(&validating_datastore);
			valid[i] = (status == EL2GO_STATUS_SUCCESS);
		}
	}

	/* Find the first valid file */
	for (i = 0; i < FILE_POINTER_NUMBER; i++) {
		if (valid[i]) {
			valid_file_idx = i;
			EL2GO_DBG_PRINTF(VERBOSE,
					 "Using file %u as read source\n",
					 valid_file_idx);
			break;
		}
	}

	/* If no valid file found, loop doesn't break and valid_file_idx stays 0 */
	if (i == FILE_POINTER_NUMBER) {
		EL2GO_DBG_PRINTF(VERBOSE,
				 "No valid files found, creating all\n");
	}

	ctx->idx_read = valid_file_idx;
	ctx->idx_write = valid_file_idx;

	/* Reopen/recreate all invalid files */
	for (i = 0; i < FILE_POINTER_NUMBER; i++) {
		if (!valid[i]) {
			/* Close invalid files before recreating */
			if (ctx->fp[i]) {
				osal_fclose(ctx->fp[i]);
				ctx->fp[i] = NULL;
			}

			status = open_file(&ctx->fp[i], ctx->filenames[i],
					   "w+b");
			if (status != EL2GO_STATUS_SUCCESS) {
				EL2GO_DBG_PRINTF(/* force clang format */
						 ERROR,
						 "Failed to create file %u\n",
						 i);
				goto cleanup;
			}
		}
	}

	status = EL2GO_STATUS_SUCCESS;
	goto exit;

cleanup:
	for (i = 0; i < FILE_POINTER_NUMBER; i++) {
		if (ctx->fp[i]) {
			osal_fclose(ctx->fp[i]);
			ctx->fp[i] = NULL;
		}
	}

exit:
	EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static el2go_status_t el2go_datastore_fs_allocate(void *context, size_t len)
{
	el2go_status_t status = EL2GO_STATUS_SUCCESS;
	el2go_datastore_fs_context_t *ctx =
		(el2go_datastore_fs_context_t *)context;

	EL2GO_DBG_TRACE_FUNCTION_CALL;

	if (!ctx || len == 0) {
		status = EL2GO_STATUS_INVALID_PARAMETER;
		goto exit;
	}

	if (ctx->idx_read >= FILE_POINTER_NUMBER ||
	    ctx->idx_write >= FILE_POINTER_NUMBER) {
		EL2GO_DBG_PRINTF(ERROR, "Invalid file pointer index\n");
		status = EL2GO_STATUS_INVALID_STATE;
		goto exit;
	}

	/**
	 * If currently read and write indices are different, there is a
	 * transaction ongoing already. In that case recover by terminating
	 * (without commit) the ongoing transaction and starting a fresh one.
	 */
	if (ctx->idx_read != ctx->idx_write) {
		EL2GO_DBG_PRINTF(VERBOSE, "Transaction ongoing, recovering\n");
		if (ctx->fp[ctx->idx_write]) {
			osal_fclose(ctx->fp[ctx->idx_write]);
			ctx->fp[ctx->idx_write] = NULL;
		}
	} else {
		ctx->idx_write = (ctx->idx_write + 1) & 0x01;
	}

	status = open_file(&ctx->fp[ctx->idx_write],
			   ctx->filenames[ctx->idx_write], "w+b");
	if (status != EL2GO_STATUS_SUCCESS) {
		EL2GO_DBG_PRINTF(ERROR, "Failed to open write file\n");
		goto exit;
	}

exit:
	EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static el2go_status_t el2go_datastore_fs_write(void *context, const void *src,
					       size_t offset, size_t len)
{
	el2go_status_t status = EL2GO_STATUS_SUCCESS;
	el2go_datastore_fs_context_t *ctx =
		(el2go_datastore_fs_context_t *)context;
	size_t written = 0;

	EL2GO_DBG_TRACE_FUNCTION_CALL;

	if (!ctx || !src || len == 0) {
		status = EL2GO_STATUS_INVALID_PARAMETER;
		goto exit;
	}

	if (ctx->idx_write >= FILE_POINTER_NUMBER) {
		EL2GO_DBG_PRINTF(ERROR, "Write index out of bounds\n");
		status = EL2GO_STATUS_INVALID_STATE;
		goto exit;
	}

	if (!ctx->fp[ctx->idx_write]) {
		EL2GO_DBG_PRINTF(ERROR, "Write file pointer is NULL\n");
		status = EL2GO_STATUS_INVALID_POINTER;
		goto exit;
	}

	if (offset > INT32_MAX) {
		EL2GO_DBG_PRINTF(ERROR, "Offset too large: %zu\n", offset);
		status = EL2GO_STATUS_INVALID_PARAMETER;
		goto exit;
	}

	if (osal_fseek(ctx->fp[ctx->idx_write], (long)offset, OSAL_SEEK_SET) !=
	    EL2GO_STATUS_SUCCESS) {
		EL2GO_DBG_PRINTF(ERROR, "Failed to seek to offset %zu\n",
				 offset);
		status = EL2GO_STATUS_FILE_SEEK_ERROR;
		goto exit;
	}

	written =
		osal_fwrite(src, sizeof(uint8_t), len, ctx->fp[ctx->idx_write]);
	if (written != len) {
		EL2GO_DBG_PRINTF(ERROR,
				 "Write error: expected %zu, wrote %zu\n", len,
				 written);
		status = EL2GO_STATUS_FILE_WRITE_ERROR;
		goto exit;
	}

exit:
	EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static el2go_status_t el2go_datastore_fs_read(void *context, void *dest,
					      size_t offset, size_t len)
{
	el2go_status_t status = EL2GO_STATUS_SUCCESS;
	el2go_datastore_fs_context_t *ctx =
		(el2go_datastore_fs_context_t *)context;
	size_t read_bytes = 0;

	EL2GO_DBG_TRACE_FUNCTION_CALL;

	if (!ctx || !dest || len == 0) {
		status = EL2GO_STATUS_INVALID_PARAMETER;
		goto exit;
	}

	if (ctx->idx_read >= FILE_POINTER_NUMBER) {
		EL2GO_DBG_PRINTF(ERROR, "Read index out of bounds\n");
		status = EL2GO_STATUS_INVALID_STATE;
		goto exit;
	}

	if (!ctx->fp[ctx->idx_read]) {
		EL2GO_DBG_PRINTF(ERROR, "Read file pointer is NULL\n");
		status = EL2GO_STATUS_INVALID_POINTER;
		goto exit;
	}

	if (offset > INT32_MAX) {
		EL2GO_DBG_PRINTF(ERROR, "Offset too large: %zu\n", offset);
		status = EL2GO_STATUS_INVALID_PARAMETER;
		goto exit;
	}

	if (osal_fseek(ctx->fp[ctx->idx_read], (long)offset, OSAL_SEEK_SET) !=
	    EL2GO_STATUS_SUCCESS) {
		EL2GO_DBG_PRINTF(ERROR, "Failed to seek to offset %zu\n",
				 offset);
		status = EL2GO_STATUS_FILE_SEEK_ERROR;
		goto exit;
	}

	read_bytes =
		osal_fread(dest, sizeof(uint8_t), len, ctx->fp[ctx->idx_read]);
	if (read_bytes != len) {
		EL2GO_DBG_PRINTF(ERROR, "Read error: expected %zu, read %zu\n",
				 len, read_bytes);
		status = EL2GO_STATUS_FILE_READ_ERROR;
		goto exit;
	}

exit:
	EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static el2go_status_t el2go_datastore_fs_commit(void *context)
{
	el2go_status_t status = EL2GO_STATUS_SUCCESS;
	el2go_datastore_fs_context_t *ctx =
		(el2go_datastore_fs_context_t *)context;
	unsigned int new_write_idx = 0;

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

	if (osal_fflush(ctx->fp[ctx->idx_write]) != EL2GO_STATUS_SUCCESS) {
		EL2GO_DBG_PRINTF(ERROR, "Failed to flush write file\n");
		status = EL2GO_STATUS_FILE_WRITE_ERROR;
		goto exit;
	}

	new_write_idx = ctx->idx_read;
	ctx->idx_read = ctx->idx_write;

	if (ctx->fp[new_write_idx]) {
		osal_fclose(ctx->fp[new_write_idx]);
		ctx->fp[new_write_idx] = NULL;
	}

	status = open_file(&ctx->fp[new_write_idx],
			   ctx->filenames[new_write_idx], "w+b");
	if (status != EL2GO_STATUS_SUCCESS) {
		EL2GO_DBG_PRINTF(ERROR, "Failed to reopen read file\n");
		goto exit;
	}

exit:
	EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

static el2go_status_t el2go_datastore_fs_free(void *context)
{
	el2go_status_t status = EL2GO_STATUS_SUCCESS;
	el2go_datastore_fs_context_t *ctx =
		(el2go_datastore_fs_context_t *)context;
	unsigned int i = 0;

	EL2GO_DBG_TRACE_FUNCTION_CALL;

	if (!ctx)
		goto exit;

	for (; i < FILE_POINTER_NUMBER; i++) {
		if (ctx->fp[i]) {
			osal_fclose(ctx->fp[i]);
			ctx->fp[i] = NULL;
		}

		if (ctx->filenames[i]) {
			osal_free(ctx->filenames[i]);
			ctx->filenames[i] = NULL;
		}
	}

	ctx->idx_read = 0;
	ctx->idx_write = 0;

	osal_free(ctx);

exit:
	EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}
