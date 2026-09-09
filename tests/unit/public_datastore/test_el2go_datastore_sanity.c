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
/* Parameter Validation Tests                                                 */
/* ========================================================================== */

/**
 * @brief Verify that el2go_datastore_init() rejects a NULL datastore pointer or a NULL basename.
 *
 * Checks that passing NULL as the datastore output argument returns
 * EL2GO_STATUS_INVALID_PARAMETER, and that passing NULL as the basename
 * also returns EL2GO_STATUS_INVALID_PARAMETER.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_datastore_init_null_parameters(void *params)
{
    el2go_datastore_t datastore = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    bool test_status = true;

    (void)params;

    status = el2go_datastore_init(1, "test", EL2GO_DATASTORE_TYPE_PLAIN, NULL, NULL);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_INVALID_PARAMETER, status, exit);

    status = el2go_datastore_init(1, NULL, EL2GO_DATASTORE_TYPE_FS, &datastore, NULL);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_INVALID_PARAMETER, status, exit);

exit:
    status = el2go_datastore_free(&datastore);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_SUCCESS, status);

    return test_status;
}

/**
 * @brief Verify that el2go_datastore_init() rejects an unknown datastore
 *        type value and returns EL2GO_STATUS_INVALID_PARAMETER.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_datastore_init_invalid_type(void *params)
{
    el2go_datastore_t datastore = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    bool test_status = true;

    (void)params;

    status = el2go_datastore_init(1, "test", 999, &datastore, NULL);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_INVALID_PARAMETER, status, exit);

exit:
    status = el2go_datastore_free(&datastore);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_SUCCESS, status);

    return test_status;
}

/**
 * @brief Verify that el2go_datastore_allocate() rejects a zero-length request.
 *
 * Expects EL2GO_STATUS_INVALID_PARAMETER when len == 0.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_datastore_allocate_zero_size(void *params)
{
    el2go_datastore_t datastore = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    bool test_status = true;

    (void)params;

    status = el2go_datastore_init(1, "test", EL2GO_DATASTORE_TYPE_PLAIN, &datastore, NULL);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    status = el2go_datastore_allocate(&datastore, 0);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_INVALID_PARAMETER, status);

exit:
    status = el2go_datastore_free(&datastore);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_SUCCESS, status);

    return test_status;
}

/**
 * @brief Verify that el2go_datastore_allocate() rejects a NULL datastore pointer.
 *
 * Expects EL2GO_STATUS_INVALID_PARAMETER when the datastore argument is NULL.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_datastore_allocate_null_pointer(void *params)
{
    el2go_status_t status = EL2GO_STATUS_SUCCESS;

    (void)params;

    status = el2go_datastore_allocate(NULL, 1024);
    TEST_ASSERT_EQUAL(EL2GO_STATUS_INVALID_PARAMETER, status);

    return true;
}

/**
 * @brief Verify that el2go_datastore_write() returns
 *        EL2GO_STATUS_INVALID_PARAMETER when any required pointer argument
 *        is NULL.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_datastore_write_null_parameters(void *params)
{
    el2go_datastore_t datastore = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    uint8_t write_data[64] = { 0 };
    size_t bytes_written = 0;
    bool test_status = true;

    (void)params;

    status = el2go_datastore_init(1, "test", EL2GO_DATASTORE_TYPE_PLAIN, &datastore, NULL);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    status = el2go_datastore_allocate(&datastore, 256);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    status = el2go_datastore_write(&datastore, NULL, 0, 64, &bytes_written);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_INVALID_PARAMETER, status, exit);

    status = el2go_datastore_write(NULL, write_data, 0, 64, &bytes_written);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_INVALID_PARAMETER, status, exit);

    status = el2go_datastore_write(&datastore, write_data, 0, 64, NULL);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_INVALID_PARAMETER, status);

exit:
    status = el2go_datastore_free(&datastore);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_SUCCESS, status);

    return test_status;
}

/**
 * @brief Verify that el2go_datastore_write() rejects a zero-length write request.
 *
 * Expects EL2GO_STATUS_INVALID_PARAMETER when len == 0.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_datastore_write_zero_length(void *params)
{
    el2go_datastore_t datastore = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    uint8_t write_data[64] = { 0 };
    size_t bytes_written = 0;
    bool test_status = true;

    (void)params;

    status = el2go_datastore_init(1, "test", EL2GO_DATASTORE_TYPE_PLAIN, &datastore, NULL);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    status = el2go_datastore_allocate(&datastore, 256);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    status = el2go_datastore_write(&datastore, write_data, 0, 0, &bytes_written);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_INVALID_PARAMETER, status);

exit:
    status = el2go_datastore_free(&datastore);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_SUCCESS, status);

    return test_status;
}

/**
 * @brief Verify that el2go_datastore_read() returns
 *        EL2GO_STATUS_INVALID_PARAMETER when any required pointer argument
 *        is NULL.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_datastore_read_null_parameters(void *params)
{
    el2go_datastore_t datastore = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    uint8_t read_data[64] = { 0 };
    size_t bytes_read = 0;
    bool test_status = true;

    (void)params;

    status = el2go_datastore_init(1, "test", EL2GO_DATASTORE_TYPE_PLAIN, &datastore, NULL);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    status = el2go_datastore_allocate(&datastore, 256);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    status = el2go_datastore_commit(&datastore);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    status = el2go_datastore_read(&datastore, NULL, 0, 64, &bytes_read);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_INVALID_PARAMETER, status, exit);

    status = el2go_datastore_read(NULL, read_data, 0, 64, &bytes_read);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_INVALID_PARAMETER, status, exit);

    status = el2go_datastore_read(&datastore, read_data, 0, 64, NULL);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_INVALID_PARAMETER, status);

exit:
    status = el2go_datastore_free(&datastore);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_SUCCESS, status);

    return test_status;
}

/**
 * @brief Verify that el2go_datastore_read() rejects a zero-length read request.
 *
 * Expects EL2GO_STATUS_INVALID_PARAMETER when len == 0.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_datastore_read_zero_length(void *params)
{
    el2go_datastore_t datastore = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    uint8_t read_data[64] = { 0 };
    size_t bytes_read = 0;
    bool test_status = true;

    (void)params;

    status = el2go_datastore_init(1, "test", EL2GO_DATASTORE_TYPE_PLAIN, &datastore, NULL);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    status = el2go_datastore_allocate(&datastore, 256);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    status = el2go_datastore_commit(&datastore);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    status = el2go_datastore_read(&datastore, read_data, 0, 0, &bytes_read);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_INVALID_PARAMETER, status);

exit:
    status = el2go_datastore_free(&datastore);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_SUCCESS, status);

    return test_status;
}

/**
 * @brief Verify that el2go_datastore_commit() fails when no transaction is active.
 *
 * Calls commit on a freshly initialized datastore (no preceding allocate) and
 * expects EL2GO_STATUS_INVALID_STATE.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_datastore_commit_without_transaction(void *params)
{
    el2go_datastore_t datastore = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    bool test_status = true;

    (void)params;

    status = el2go_datastore_init(1, "test", EL2GO_DATASTORE_TYPE_PLAIN, &datastore, NULL);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    status = el2go_datastore_commit(&datastore);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_INVALID_STATE, status);

exit:
    status = el2go_datastore_free(&datastore);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_SUCCESS, status);

    return test_status;
}

/**
 * @brief Verify that el2go_datastore_commit() rejects a NULL datastore pointer.
 *
 * Expects EL2GO_STATUS_INVALID_PARAMETER when the datastore argument is NULL.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_datastore_commit_null_pointer(void *params)
{
    el2go_status_t status = EL2GO_STATUS_SUCCESS;

    (void)params;

    status = el2go_datastore_commit(NULL);
    TEST_ASSERT_EQUAL(EL2GO_STATUS_INVALID_PARAMETER, status);

    return true;
}

/* ========================================================================== */
/* Test Registration                                                          */
/* ========================================================================== */

/**
 * @brief Register all datastore sanity tests with the test framework.
 */
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
