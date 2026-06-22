/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <string.h>
#include <stdlib.h>

#include "test_framework.h"
#include "test_utils.h"
#include "test_el2go_datastore_common.h"

#include "common/el2go_datastore.h"

/* ========================================================================== */
/* File System Datastore Tests                                                */
/* ========================================================================== */

static bool test_datastore_fs_init_and_free(void *params)
{
	(void)params;

	return common_test_ds_init_and_free(EL2GO_DATASTORE_TYPE_FS, __func__,
					    2, NULL, NULL);
}

static bool test_datastore_fs_full_transaction(void *params)
{
	(void)params;

	return common_test_ds_full_transaction(EL2GO_DATASTORE_TYPE_FS,
					       __func__, NULL, NULL);
}

static bool test_datastore_fs_multiple_transactions(void *params)
{
	(void)params;

	return common_test_ds_multiple_transactions(EL2GO_DATASTORE_TYPE_FS,
						    __func__, NULL, NULL);
}

static bool test_datastore_fs_write_at_different_offsets(void *params)
{
	(void)params;

	return common_test_ds_write_at_different_offsets(/* force clang format */
							 EL2GO_DATASTORE_TYPE_FS,
							 __func__, NULL, NULL);
}

static bool test_datastore_fs_write_out_of_bounds(void *params)
{
	(void)params;

	return common_test_ds_write_out_of_bounds(EL2GO_DATASTORE_TYPE_FS,
						  __func__, NULL, NULL,
						  EL2GO_STATUS_SUCCESS);
}

static bool test_datastore_fs_read_out_of_bounds(void *params)
{
	(void)params;

	return common_test_ds_read_out_of_bounds(EL2GO_DATASTORE_TYPE_FS,
						 __func__, NULL, NULL,
						 EL2GO_STATUS_FILE_READ_ERROR);
}

static bool test_datastore_fs_transaction_recovery(void *params)
{
	(void)params;

	return common_test_ds_transaction_recovery(EL2GO_DATASTORE_TYPE_FS,
						   __func__, NULL, NULL);
}

static bool test_datastore_fs_large_allocation(void *params)
{
	(void)params;

	return common_test_ds_large_allocation(EL2GO_DATASTORE_TYPE_FS,
					       __func__, NULL, NULL);
}

/* ========================================================================== */
/* Datastore Persistence Test (FS only)                                       */
/* ========================================================================== */

static el2go_status_t dummy_validator(el2go_datastore_t *datastore)
{
	el2go_status_t status = EL2GO_STATUS_SUCCESS;
	uint8_t test_byte = 0;

	if (!datastore) {
		status = EL2GO_STATUS_INVALID_POINTER;
		goto exit;
	}

	/* For FS datastore, verify that the read file contains data */
	if (datastore->type == EL2GO_DATASTORE_TYPE_FS) {
		status = el2go_datastore_read(datastore, &test_byte, 0, 1);
		goto exit;
	}

	/* For other datastore types, no validation needed */
	status = EL2GO_STATUS_SUCCESS;

exit:
	return status;
}

static bool test_datastore_fs_persistence(void *params)
{
	el2go_datastore_t datastore[2] = { 0 };
	el2go_status_t status = EL2GO_STATUS_SUCCESS;
	uint8_t write_data[64] = { 0 };
	uint8_t read_data[64] = { 0 };
	bool test_status = true;
	bool initialized[2] = { false };
	unsigned int i = 0;

	(void)params;

	status = el2go_datastore_init(1, __func__, EL2GO_DATASTORE_TYPE_FS,
				      &datastore[0], NULL);
	TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

	initialized[0] = true;

	status = el2go_datastore_allocate(&datastore[0], 256);
	TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

	fill_buffer(write_data, sizeof(write_data), 50);

	status = el2go_datastore_write(&datastore[0], write_data, 0,
				       sizeof(write_data));
	TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

	status = el2go_datastore_commit(&datastore[0]);
	TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

	status = el2go_datastore_free(&datastore[0]);
	TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

	initialized[0] = false;

	status = el2go_datastore_init(2, __func__, EL2GO_DATASTORE_TYPE_FS,
				      &datastore[1], dummy_validator);
	TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

	initialized[1] = true;

	status = el2go_datastore_read(&datastore[1], read_data, 0,
				      sizeof(read_data));
	TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

	if (memcmp(write_data, read_data, sizeof(write_data))) {
		TEST_PRINT_FAIL("Memory comparison failed");
		test_status = false;
	}

exit:
	for (; i < 2; i++) {
		if (initialized[i]) {
			status = el2go_datastore_free(&datastore[i]);
			TEST_ASSERT_EQUAL_CONTINUE(status,
						   EL2GO_STATUS_SUCCESS);
		}
	}

	return test_status;
}

/* ========================================================================== */
/* Test Registration                                                          */
/* ========================================================================== */

void register_datastore_fs_tests(void)
{
	/* Initialization tests */
	TEST_REGISTER(test_datastore_fs_init_and_free);

	/* Transaction workflow tests */
	TEST_REGISTER(test_datastore_fs_full_transaction);
	TEST_REGISTER(test_datastore_fs_multiple_transactions);
	TEST_REGISTER(test_datastore_fs_write_at_different_offsets);

	/* Edge case tests */
	TEST_REGISTER(test_datastore_fs_write_out_of_bounds);
	TEST_REGISTER(test_datastore_fs_read_out_of_bounds);
	TEST_REGISTER(test_datastore_fs_transaction_recovery);
	TEST_REGISTER(test_datastore_fs_large_allocation);

	/* Persistence tests */
	TEST_REGISTER(test_datastore_fs_persistence);
}
