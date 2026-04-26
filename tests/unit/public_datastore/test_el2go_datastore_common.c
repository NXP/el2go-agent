// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright 2026 NXP
 */

#include <string.h>
#include <stdlib.h>

#include "test_framework.h"
#include "test_utils.h"
#include "test_suites.h"
#include "test_el2go_datastore_common.h"

#include "rtp/el2go_rtp.h"
#include "common/el2go_datastore.h"

/* ========================================================================== */
/* Suite Context                                                              */
/* ========================================================================== */

static suite_context_t suite_ctx = { 0 };

/* ========================================================================== */
/* Suite Setup and Teardown Functions                                         */
/* ========================================================================== */

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
/* Helper Functions                                                           */
/* ========================================================================== */

static el2go_status_t init_datastore(el2go_datastore_t *datastore,
				     el2go_datastore_type_t type,
				     const char *name, uint32_t id,
				     const el2go_datastore_ops_t *ops,
				     void *ctx)
{
	if (type == EL2GO_DATASTORE_TYPE_CUSTOM) {
		datastore->ops = ops;
		datastore->context = ctx;
	}

	return el2go_datastore_init(id, name, type, datastore, NULL);
}

/* ========================================================================== */
/* Common Test Functions                                                      */
/* ========================================================================== */

bool common_test_ds_init_and_free(el2go_datastore_type_t type, const char *name,
				  uint32_t id, const el2go_datastore_ops_t *ops,
				  void *ctx)
{
	el2go_datastore_t datastore = { 0 };
	el2go_status_t status = EL2GO_STATUS_SUCCESS;
	bool test_status = true;

	status = init_datastore(&datastore, type, name, id, ops, ctx);
	TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

	TEST_ASSERT_EQUAL_GOTO(datastore.id, id, cleanup);
	TEST_ASSERT_EQUAL_GOTO(datastore.type, type, cleanup);
	TEST_ASSERT_NOT_NULL_GOTO(datastore.name, cleanup);
	TEST_ASSERT_NOT_NULL_GOTO(datastore.ops, cleanup);
	TEST_ASSERT_NOT_NULL_CONTINUE(datastore.context);

cleanup:
	status = el2go_datastore_free(&datastore);
	TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

	TEST_ASSERT_NULL_GOTO(datastore.context, exit);
	TEST_ASSERT_NULL_CONTINUE(datastore.ops);

exit:
	return test_status;
}

bool common_test_ds_full_transaction(el2go_datastore_type_t type,
				     const char *name,
				     const el2go_datastore_ops_t *ops,
				     void *ctx)
{
	el2go_datastore_t datastore = { 0 };
	el2go_status_t status = EL2GO_STATUS_SUCCESS;
	uint8_t write_data[100] = { 0 };
	uint8_t read_data[100] = { 0 };
	bool test_status = true;

	fill_buffer(write_data, sizeof(write_data), 0);

	status = init_datastore(&datastore, type, name, 1, ops, ctx);
	TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

	status = el2go_datastore_allocate(&datastore, 512);
	TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, cleanup);

	status = el2go_datastore_write(&datastore, write_data, 0,
				       sizeof(write_data));
	TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, cleanup);

	status = el2go_datastore_commit(&datastore);
	TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, cleanup);

	status = el2go_datastore_read(&datastore, read_data, 0,
				      sizeof(read_data));
	TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, cleanup);

	TEST_ASSERT_MEMORY_EQUAL_CONTINUE(write_data, read_data,
					  sizeof(write_data));

cleanup:
	status = el2go_datastore_free(&datastore);
	TEST_ASSERT_EQUAL_CONTINUE(status, EL2GO_STATUS_SUCCESS);

exit:
	return test_status;
}

bool common_test_ds_multiple_transactions(el2go_datastore_type_t type,
					  const char *name,
					  const el2go_datastore_ops_t *ops,
					  void *ctx)
{
	el2go_datastore_t datastore = { 0 };
	el2go_status_t status = EL2GO_STATUS_SUCCESS;
	uint8_t write_data1[50] = { 0 };
	uint8_t write_data2[50] = { 0 };
	uint8_t read_data[50] = { 0 };
	bool test_status = true;

	status = init_datastore(&datastore, type, name, 1, ops, ctx);
	TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

	status = el2go_datastore_allocate(&datastore, 256);
	TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, cleanup);

	fill_buffer(write_data1, sizeof(write_data1), 0);

	status = el2go_datastore_write(&datastore, write_data1, 0,
				       sizeof(write_data1));
	TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, cleanup);

	status = el2go_datastore_commit(&datastore);
	TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, cleanup);

	status = el2go_datastore_read(&datastore, read_data, 0,
				      sizeof(read_data));
	TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, cleanup);

	TEST_ASSERT_MEMORY_EQUAL_GOTO(write_data1, read_data,
				      sizeof(write_data1), cleanup);

	status = el2go_datastore_allocate(&datastore, 256);
	TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, cleanup);

	fill_buffer(write_data2, sizeof(write_data2), 100);

	status = el2go_datastore_write(&datastore, write_data2, 0,
				       sizeof(write_data2));
	TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, cleanup);

	status = el2go_datastore_commit(&datastore);
	TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, cleanup);

	memset(read_data, 0, sizeof(read_data));
	status = el2go_datastore_read(&datastore, read_data, 0,
				      sizeof(read_data));
	TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, cleanup);

	TEST_ASSERT_MEMORY_EQUAL_CONTINUE(write_data2, read_data,
					  sizeof(write_data2));

cleanup:
	status = el2go_datastore_free(&datastore);
	TEST_ASSERT_EQUAL_CONTINUE(status, EL2GO_STATUS_SUCCESS);

exit:
	return test_status;
}

bool common_test_ds_write_at_different_offsets(el2go_datastore_type_t type,
					       const char *name,
					       const el2go_datastore_ops_t *ops,
					       void *ctx)
{
	el2go_datastore_t datastore = { 0 };
	el2go_status_t status = EL2GO_STATUS_SUCCESS;
	uint8_t write_data1[32] = { 0 };
	uint8_t write_data2[32] = { 0 };
	uint8_t read_data1[32] = { 0 };
	uint8_t read_data2[32] = { 0 };
	bool test_status = true;

	status = init_datastore(&datastore, type, name, 1, ops, ctx);
	TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

	status = el2go_datastore_allocate(&datastore, 512);
	TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, cleanup);

	fill_buffer(write_data1, sizeof(write_data1), 0);
	fill_buffer(write_data2, sizeof(write_data2), 50);

	status = el2go_datastore_write(&datastore, write_data1, 0,
				       sizeof(write_data1));
	TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, cleanup);

	status = el2go_datastore_write(&datastore, write_data2, 100,
				       sizeof(write_data2));
	TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, cleanup);

	status = el2go_datastore_commit(&datastore);
	TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, cleanup);

	status = el2go_datastore_read(&datastore, read_data1, 0,
				      sizeof(read_data1));
	TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, cleanup);

	TEST_ASSERT_MEMORY_EQUAL_GOTO(write_data1, read_data1,
				      sizeof(write_data1), cleanup);

	status = el2go_datastore_read(&datastore, read_data2, 100,
				      sizeof(read_data2));
	TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, cleanup);

	TEST_ASSERT_MEMORY_EQUAL_CONTINUE(write_data2, read_data2,
					  sizeof(write_data2));

cleanup:
	status = el2go_datastore_free(&datastore);
	TEST_ASSERT_EQUAL_CONTINUE(status, EL2GO_STATUS_SUCCESS);

exit:
	return test_status;
}

bool common_test_ds_write_out_of_bounds(el2go_datastore_type_t type,
					const char *name,
					const el2go_datastore_ops_t *ops,
					void *ctx,
					el2go_status_t expected_status)
{
	el2go_datastore_t datastore = { 0 };
	el2go_status_t status = EL2GO_STATUS_SUCCESS;
	uint8_t write_data[128] = { 0 };
	bool test_status = true;

	status = init_datastore(&datastore, type, name, 1, ops, ctx);
	TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

	status = el2go_datastore_allocate(&datastore, 100);
	TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, cleanup);

	status = el2go_datastore_write(&datastore, write_data, 0,
				       sizeof(write_data));
	TEST_ASSERT_EQUAL_GOTO(status, expected_status, cleanup);

	status = el2go_datastore_write(&datastore, write_data, 50, 100);
	TEST_ASSERT_EQUAL_CONTINUE(status, expected_status);

cleanup:
	status = el2go_datastore_free(&datastore);
	TEST_ASSERT_EQUAL_CONTINUE(status, EL2GO_STATUS_SUCCESS);

exit:
	return test_status;
}

bool common_test_ds_read_out_of_bounds(el2go_datastore_type_t type,
				       const char *name,
				       const el2go_datastore_ops_t *ops,
				       void *ctx,
				       el2go_status_t expected_status)
{
	el2go_datastore_t datastore = { 0 };
	el2go_status_t status = EL2GO_STATUS_SUCCESS;
	uint8_t write_data[64] = { 0 };
	uint8_t read_data[128] = { 0 };
	bool test_status = true;

	status = init_datastore(&datastore, type, name, 1, ops, ctx);
	TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

	status = el2go_datastore_allocate(&datastore, 100);
	TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, cleanup);

	fill_buffer(write_data, sizeof(write_data), 0);

	status = el2go_datastore_write(&datastore, write_data, 0,
				       sizeof(write_data));
	TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, cleanup);

	status = el2go_datastore_commit(&datastore);
	TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, cleanup);

	status = el2go_datastore_read(&datastore, read_data, 0,
				      sizeof(read_data));
	TEST_ASSERT_EQUAL_GOTO(status, expected_status, cleanup);

	status = el2go_datastore_read(&datastore, read_data, 50, 100);
	TEST_ASSERT_EQUAL_CONTINUE(status, expected_status);

cleanup:
	status = el2go_datastore_free(&datastore);
	TEST_ASSERT_EQUAL_CONTINUE(status, EL2GO_STATUS_SUCCESS);

exit:
	return test_status;
}

bool common_test_ds_transaction_recovery(el2go_datastore_type_t type,
					 const char *name,
					 const el2go_datastore_ops_t *ops,
					 void *ctx)
{
	el2go_datastore_t datastore = { 0 };
	el2go_status_t status = EL2GO_STATUS_SUCCESS;
	uint8_t write_data1[32] = { 0 };
	uint8_t write_data2[32] = { 0 };
	uint8_t read_data[32] = { 0 };
	bool test_status = true;

	status = init_datastore(&datastore, type, name, 1, ops, ctx);
	TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

	status = el2go_datastore_allocate(&datastore, 128);
	TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, cleanup);

	fill_buffer(write_data1, sizeof(write_data1), 0);

	status = el2go_datastore_write(&datastore, write_data1, 0,
				       sizeof(write_data1));
	TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, cleanup);

	status = el2go_datastore_commit(&datastore);
	TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, cleanup);

	status = el2go_datastore_allocate(&datastore, 128);
	TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, cleanup);

	fill_buffer(write_data2, sizeof(write_data2), 50);

	status = el2go_datastore_write(&datastore, write_data2, 0,
				       sizeof(write_data2));
	TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, cleanup);

	status = el2go_datastore_allocate(&datastore, 128);
	TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, cleanup);

	status = el2go_datastore_read(&datastore, read_data, 0,
				      sizeof(read_data));
	TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, cleanup);

	TEST_ASSERT_MEMORY_EQUAL_CONTINUE(write_data1, read_data,
					  sizeof(write_data1));

cleanup:
	status = el2go_datastore_free(&datastore);
	TEST_ASSERT_EQUAL_CONTINUE(status, EL2GO_STATUS_SUCCESS);

exit:
	return test_status;
}

bool common_test_ds_large_allocation(el2go_datastore_type_t type,
				     const char *name,
				     const el2go_datastore_ops_t *ops,
				     void *ctx)
{
	el2go_datastore_t datastore = { 0 };
	el2go_status_t status = EL2GO_STATUS_SUCCESS;
	uint8_t *large_data = NULL;
	uint8_t *read_data = NULL;
	size_t large_size = 1024 * 1024; /* 1 MB */
	bool test_status = true;

	status = init_datastore(&datastore, type, name, 1, ops, ctx);
	TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

	status = el2go_datastore_allocate(&datastore, large_size);
	TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, cleanup);

	large_data = (uint8_t *)calloc(large_size, sizeof(uint8_t));
	TEST_ASSERT_NOT_NULL_GOTO(large_data, cleanup);

	read_data = (uint8_t *)calloc(large_size, sizeof(uint8_t));
	TEST_ASSERT_NOT_NULL_GOTO(read_data, cleanup);

	fill_buffer(large_data, large_size, 0);

	status = el2go_datastore_write(&datastore, large_data, 0, large_size);
	TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, cleanup);

	status = el2go_datastore_commit(&datastore);
	TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, cleanup);

	status = el2go_datastore_read(&datastore, read_data, 0, large_size);
	TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, cleanup);

	TEST_ASSERT_MEMORY_EQUAL_CONTINUE(large_data, read_data, large_size);

cleanup:
	status = el2go_datastore_free(&datastore);
	TEST_ASSERT_EQUAL_CONTINUE(status, EL2GO_STATUS_SUCCESS);

	if (large_data)
		free(large_data);

	if (read_data)
		free(read_data);

exit:
	return test_status;
}

/* ========================================================================== */
/* Test Registration                                                          */
/* ========================================================================== */

void register_datastore_tests(void)
{
	/* Set suite-level setup and teardown */
	TEST_SET_SUITE_SETUP(suite_setup);
	TEST_SET_SUITE_TEARDOWN(suite_teardown);

	/* Register tests from different modules */
	register_datastore_sanity_tests();
	register_datastore_fs_tests();
	register_datastore_plain_tests();
	register_datastore_custom_tests();
}
