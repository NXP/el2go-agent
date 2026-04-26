// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright 2026 NXP
 */

#include <string.h>
#include <stdlib.h>

#include "test_framework.h"
#include "test_el2go_datastore_common.h"

#include "common/el2go_datastore.h"

/* ========================================================================== */
/* Parameter Validation Tests                                                 */
/* ========================================================================== */

static bool test_datastore_init_null_parameters(void *params)
{
	el2go_datastore_t datastore = { 0 };
	el2go_status_t status = EL2GO_STATUS_SUCCESS;
	bool test_status = true;

	(void)params;

	status = el2go_datastore_init(1, "test", EL2GO_DATASTORE_TYPE_PLAIN,
				      NULL, NULL);
	TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_INVALID_PARAMETER, exit);

	status = el2go_datastore_init(1, NULL, EL2GO_DATASTORE_TYPE_FS,
				      &datastore, NULL);
	TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_INVALID_PARAMETER, exit);

exit:
	status = el2go_datastore_free(&datastore);
	TEST_ASSERT_EQUAL_CONTINUE(status, EL2GO_STATUS_SUCCESS);

	return test_status;
}

static bool test_datastore_init_invalid_type(void *params)
{
	el2go_datastore_t datastore = { 0 };
	el2go_status_t status = EL2GO_STATUS_SUCCESS;
	bool test_status = true;

	(void)params;

	status = el2go_datastore_init(1, "test", 999, &datastore, NULL);
	TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_INVALID_PARAMETER, exit);

exit:
	status = el2go_datastore_free(&datastore);
	TEST_ASSERT_EQUAL_CONTINUE(status, EL2GO_STATUS_SUCCESS);

	return test_status;
}

static bool test_datastore_allocate_zero_size(void *params)
{
	el2go_datastore_t datastore = { 0 };
	el2go_status_t status = EL2GO_STATUS_SUCCESS;
	bool test_status = true;

	(void)params;

	status = el2go_datastore_init(1, "test", EL2GO_DATASTORE_TYPE_PLAIN,
				      &datastore, NULL);
	TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

	status = el2go_datastore_allocate(&datastore, 0);
	TEST_ASSERT_EQUAL_CONTINUE(status, EL2GO_STATUS_INVALID_PARAMETER);

exit:
	status = el2go_datastore_free(&datastore);
	TEST_ASSERT_EQUAL_CONTINUE(status, EL2GO_STATUS_SUCCESS);

	return test_status;
}

static bool test_datastore_allocate_null_pointer(void *params)
{
	el2go_status_t status = EL2GO_STATUS_SUCCESS;

	(void)params;

	status = el2go_datastore_allocate(NULL, 1024);
	TEST_ASSERT_EQUAL(status, EL2GO_STATUS_INVALID_PARAMETER);

	return true;
}

static bool test_datastore_write_null_parameters(void *params)
{
	el2go_datastore_t datastore = { 0 };
	el2go_status_t status = EL2GO_STATUS_SUCCESS;
	uint8_t write_data[64] = { 0 };
	bool test_status = true;

	(void)params;

	status = el2go_datastore_init(1, "test", EL2GO_DATASTORE_TYPE_PLAIN,
				      &datastore, NULL);
	TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

	status = el2go_datastore_allocate(&datastore, 256);
	TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

	status = el2go_datastore_write(&datastore, NULL, 0, 64);
	TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_INVALID_PARAMETER, exit);

	status = el2go_datastore_write(NULL, write_data, 0, 64);
	TEST_ASSERT_EQUAL_CONTINUE(status, EL2GO_STATUS_INVALID_PARAMETER);

exit:
	status = el2go_datastore_free(&datastore);
	TEST_ASSERT_EQUAL_CONTINUE(status, EL2GO_STATUS_SUCCESS);

	return test_status;
}

static bool test_datastore_write_zero_length(void *params)
{
	el2go_datastore_t datastore = { 0 };
	el2go_status_t status = EL2GO_STATUS_SUCCESS;
	uint8_t write_data[64] = { 0 };
	bool test_status = true;

	(void)params;

	status = el2go_datastore_init(1, "test", EL2GO_DATASTORE_TYPE_PLAIN,
				      &datastore, NULL);
	TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

	status = el2go_datastore_allocate(&datastore, 256);
	TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

	status = el2go_datastore_write(&datastore, write_data, 0, 0);
	TEST_ASSERT_EQUAL_CONTINUE(status, EL2GO_STATUS_INVALID_PARAMETER);

exit:
	status = el2go_datastore_free(&datastore);
	TEST_ASSERT_EQUAL_CONTINUE(status, EL2GO_STATUS_SUCCESS);

	return test_status;
}

static bool test_datastore_read_null_parameters(void *params)
{
	el2go_datastore_t datastore = { 0 };
	el2go_status_t status = EL2GO_STATUS_SUCCESS;
	uint8_t read_data[64] = { 0 };
	bool test_status = true;

	(void)params;

	status = el2go_datastore_init(1, "test", EL2GO_DATASTORE_TYPE_PLAIN,
				      &datastore, NULL);
	TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

	status = el2go_datastore_allocate(&datastore, 256);
	TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

	status = el2go_datastore_commit(&datastore);
	TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

	status = el2go_datastore_read(&datastore, NULL, 0, 64);
	TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_INVALID_PARAMETER, exit);

	status = el2go_datastore_read(NULL, read_data, 0, 64);
	TEST_ASSERT_EQUAL_CONTINUE(status, EL2GO_STATUS_INVALID_PARAMETER);

exit:
	status = el2go_datastore_free(&datastore);
	TEST_ASSERT_EQUAL_CONTINUE(status, EL2GO_STATUS_SUCCESS);

	return test_status;
}

static bool test_datastore_read_zero_length(void *params)
{
	el2go_datastore_t datastore = { 0 };
	el2go_status_t status = EL2GO_STATUS_SUCCESS;
	uint8_t read_data[64] = { 0 };
	bool test_status = true;

	(void)params;

	status = el2go_datastore_init(1, "test", EL2GO_DATASTORE_TYPE_PLAIN,
				      &datastore, NULL);
	TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

	status = el2go_datastore_allocate(&datastore, 256);
	TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

	status = el2go_datastore_commit(&datastore);
	TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

	status = el2go_datastore_read(&datastore, read_data, 0, 0);
	TEST_ASSERT_EQUAL_CONTINUE(status, EL2GO_STATUS_INVALID_PARAMETER);

exit:
	status = el2go_datastore_free(&datastore);
	TEST_ASSERT_EQUAL_CONTINUE(status, EL2GO_STATUS_SUCCESS);

	return test_status;
}

static bool test_datastore_commit_without_transaction(void *params)
{
	el2go_datastore_t datastore = { 0 };
	el2go_status_t status = EL2GO_STATUS_SUCCESS;
	bool test_status = true;

	(void)params;

	status = el2go_datastore_init(1, "test", EL2GO_DATASTORE_TYPE_PLAIN,
				      &datastore, NULL);
	TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

	status = el2go_datastore_commit(&datastore);
	TEST_ASSERT_EQUAL_CONTINUE(status, EL2GO_STATUS_INVALID_STATE);

exit:
	status = el2go_datastore_free(&datastore);
	TEST_ASSERT_EQUAL_CONTINUE(status, EL2GO_STATUS_SUCCESS);

	return test_status;
}

static bool test_datastore_commit_null_pointer(void *params)
{
	el2go_status_t status = EL2GO_STATUS_SUCCESS;

	(void)params;

	status = el2go_datastore_commit(NULL);
	TEST_ASSERT_EQUAL(status, EL2GO_STATUS_INVALID_PARAMETER);

	return true;
}

/* ========================================================================== */
/* Test Registration                                                          */
/* ========================================================================== */

void register_datastore_sanity_tests(void)
{
	/* Parameter validation tests */
	TEST_REGISTER(test_datastore_init_null_parameters);
	TEST_REGISTER(test_datastore_init_invalid_type);

	TEST_REGISTER(test_datastore_allocate_zero_size);
	TEST_REGISTER(test_datastore_allocate_null_pointer);

	TEST_REGISTER(test_datastore_write_null_parameters);
	TEST_REGISTER(test_datastore_write_zero_length);

	TEST_REGISTER(test_datastore_read_null_parameters);
	TEST_REGISTER(test_datastore_read_zero_length);

	TEST_REGISTER(test_datastore_commit_without_transaction);
	TEST_REGISTER(test_datastore_commit_null_pointer);
}
