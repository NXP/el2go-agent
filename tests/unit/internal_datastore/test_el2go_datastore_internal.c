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

#include "el2go_datastore_plain.h"
#include "el2go_datastore_fs.h"
#include "common/el2go_datastore.h"

/* Forward declaration - implemented in test_el2go_datastore_handle_request.c */
void register_datastore_handle_request_tests(bool include_fs_tests);
void register_datastore_get_size_tests(bool include_fs_tests);

/* ========================================================================== */
/* Suite Setup                                                                */
/* ========================================================================== */

static void suite_setup(void *params)
{
    (void)params;

    osal_lib_init();
}

/* ========================================================================== */
/* Helper Functions                                                           */
/* ========================================================================== */

static el2go_status_t cleanup_datastore(el2go_datastore_t *datastore)
{
    el2go_status_t status = EL2GO_STATUS_SUCCESS;

    if (!datastore)
        return EL2GO_STATUS_INVALID_POINTER;

    if (datastore->context) {
        if (datastore->ops && datastore->ops->free) {
            status = datastore->ops->free(datastore->context);
            if (status != EL2GO_STATUS_SUCCESS) {
                TEST_PRINT_FAIL("Expected %d, got %d", EL2GO_STATUS_SUCCESS, status);
                return status;
            }
        } else {
            osal_free(datastore->context);
        }
    }

    return EL2GO_STATUS_SUCCESS;
}

bool check_datastore(const el2go_datastore_t datastore)
{
    TEST_ASSERT_NOT_NULL(datastore.context);
    TEST_ASSERT_NOT_NULL(datastore.ops);
    TEST_ASSERT_NOT_NULL(datastore.ops->init);
    TEST_ASSERT_NOT_NULL(datastore.ops->allocate);
    TEST_ASSERT_NOT_NULL(datastore.ops->read);
    TEST_ASSERT_NOT_NULL(datastore.ops->write);
    TEST_ASSERT_NOT_NULL(datastore.ops->commit);
    TEST_ASSERT_NOT_NULL(datastore.ops->free);

    return true;
}

/* ========================================================================== */
/* Test: Plain Datastore Internal Structure                                   */
/* ========================================================================== */

/**
 * @brief Verify that el2go_datastore_plain_create() populates the datastore structure
 *        correctly and that the init callback can be called on the resulting context.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_datastore_plain_context_structure(void *params)
{
    el2go_datastore_t datastore = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    bool test_status = true;

    (void)params;

    status = el2go_datastore_plain_create(&datastore, NULL);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    if (!check_datastore(datastore))
        goto exit;

    status = datastore.ops->init(datastore.context, NULL);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_SUCCESS, status);

exit:
    status = cleanup_datastore(&datastore);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_SUCCESS, status);

    return test_status;
}

/**
 * @brief Verify that the plain datastore correctly replaces its committed buffer
 *        when a second transaction is committed over a first.
 *
 * Writes distinct data in two consecutive transactions and confirms that the
 * read after the second commit returns only the second dataset.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_datastore_plain_buffer_switching(void *params)
{
    el2go_datastore_t datastore = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    uint8_t write_data1[32] = { 0 };
    uint8_t write_data2[32] = { 0 };
    uint8_t read_data[32] = { 0 };
    size_t bytes_written = 0;
    size_t bytes_read = 0;
    bool test_status = true;

    (void)params;

    status = el2go_datastore_plain_create(&datastore, NULL);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    if (!check_datastore(datastore))
        goto exit;

    status = datastore.ops->init(datastore.context, NULL);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    status = datastore.ops->allocate(datastore.context, 128);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    fill_buffer(write_data1, sizeof(write_data1), 0);

    status = datastore.ops->write(datastore.context, write_data1, 0, sizeof(write_data1),
                                  &bytes_written);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    TEST_ASSERT_EQUAL_GOTO(sizeof(write_data1), bytes_written, exit);

    status = datastore.ops->commit(datastore.context);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    status = datastore.ops->allocate(datastore.context, 128);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    fill_buffer(write_data2, sizeof(write_data2), 100);

    status = datastore.ops->write(datastore.context, write_data2, 0, sizeof(write_data2),
                                  &bytes_written);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    TEST_ASSERT_EQUAL_GOTO(sizeof(write_data2), bytes_written, exit);

    status = datastore.ops->commit(datastore.context);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    status = datastore.ops->read(datastore.context, read_data, 0, sizeof(read_data), &bytes_read);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    TEST_ASSERT_EQUAL_GOTO(sizeof(read_data), bytes_read, exit);

    TEST_ASSERT_MEMORY_EQUAL_CONTINUE(write_data2, read_data, sizeof(write_data2));

exit:
    status = cleanup_datastore(&datastore);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_SUCCESS, status);

    return test_status;
}

/**
 * @brief Verify that all plain datastore ops return EL2GO_STATUS_INVALID_PARAMETER
 *        when called with a NULL context pointer.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_datastore_plain_null_context(void *params)
{
    el2go_datastore_t datastore = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    uint8_t data[32] = { 0 };
    size_t bytes = 0;
    bool test_status = true;

    (void)params;

    status = el2go_datastore_plain_create(&datastore, NULL);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    if (!check_datastore(datastore))
        goto exit;

    status = datastore.ops->init(NULL, NULL);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_INVALID_PARAMETER, status, exit);

    status = datastore.ops->allocate(NULL, 128);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_INVALID_PARAMETER, status, exit);

    status = datastore.ops->read(NULL, data, 0, 32, &bytes);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_INVALID_PARAMETER, status, exit);

    status = datastore.ops->write(NULL, data, 0, 32, &bytes);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_INVALID_PARAMETER, status, exit);

    status = datastore.ops->commit(NULL);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_INVALID_PARAMETER, status, exit);

    status = datastore.ops->free(NULL);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_SUCCESS, status);

exit:
    status = cleanup_datastore(&datastore);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_SUCCESS, status);

    return test_status;
}

/* ========================================================================== */
/* Test: FS Datastore Internal Structure                                      */
/* ========================================================================== */

/**
 * @brief Verify that el2go_datastore_fs_create() populates the datastore structure
 *        correctly and that the init callback can be called on the resulting context.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_datastore_fs_context_structure(void *params)
{
    el2go_datastore_t datastore = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    bool test_status = true;

    (void)params;

    status = el2go_datastore_fs_create(&datastore, __func__);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    if (!check_datastore(datastore))
        goto exit;

    status = datastore.ops->init(datastore.context, NULL);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_SUCCESS, status);

exit:
    status = cleanup_datastore(&datastore);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_SUCCESS, status);

    return test_status;
}

/**
 * @brief Verify that the filesystem datastore correctly replaces its backing file
 *        when a second transaction is committed over a first.
 *
 * Writes distinct data in two consecutive transactions and confirms that the
 * read after the second commit returns only the second dataset.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_datastore_fs_file_switching(void *params)
{
    el2go_datastore_t datastore = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    uint8_t write_data1[64] = { 0 };
    uint8_t write_data2[64] = { 0 };
    uint8_t read_data[64] = { 0 };
    size_t bytes_written = 0;
    size_t bytes_read = 0;
    bool test_status = true;

    (void)params;

    status = el2go_datastore_fs_create(&datastore, __func__);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    if (!check_datastore(datastore))
        goto exit;

    status = datastore.ops->init(datastore.context, NULL);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    status = datastore.ops->allocate(datastore.context, 256);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    fill_buffer(write_data1, sizeof(write_data1), 0);

    status = datastore.ops->write(datastore.context, write_data1, 0, sizeof(write_data1),
                                  &bytes_written);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    TEST_ASSERT_EQUAL_GOTO(sizeof(write_data1), bytes_written, exit);

    status = datastore.ops->commit(datastore.context);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    status = datastore.ops->allocate(datastore.context, 256);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    fill_buffer(write_data2, sizeof(write_data2), 50);

    status = datastore.ops->write(datastore.context, write_data2, 0, sizeof(write_data2),
                                  &bytes_written);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    TEST_ASSERT_EQUAL_GOTO(sizeof(write_data2), bytes_written, exit);

    status = datastore.ops->commit(datastore.context);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    status = datastore.ops->read(datastore.context, read_data, 0, sizeof(read_data), &bytes_read);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    TEST_ASSERT_EQUAL_GOTO(sizeof(read_data), bytes_read, exit);

    TEST_ASSERT_MEMORY_EQUAL_CONTINUE(write_data2, read_data, sizeof(write_data2));

exit:
    status = cleanup_datastore(&datastore);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_SUCCESS, status);

    return test_status;
}

/**
 * @brief Verify that all filesystem datastore ops return EL2GO_STATUS_INVALID_PARAMETER
 *        when called with a NULL context pointer.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_datastore_fs_null_context(void *params)
{
    el2go_datastore_t datastore = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    uint8_t data[32] = { 0 };
    size_t bytes = 0;
    bool test_status = true;

    (void)params;

    status = el2go_datastore_fs_create(&datastore, __func__);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    if (!check_datastore(datastore))
        goto exit;

    status = datastore.ops->init(NULL, NULL);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_INVALID_PARAMETER, status, exit);

    status = datastore.ops->allocate(NULL, 128);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_INVALID_PARAMETER, status, exit);

    status = datastore.ops->read(NULL, data, 0, 32, &bytes);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_INVALID_PARAMETER, status, exit);

    status = datastore.ops->write(NULL, data, 0, 32, &bytes);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_INVALID_PARAMETER, status, exit);

    status = datastore.ops->commit(NULL);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_INVALID_PARAMETER, status, exit);

    status = datastore.ops->free(NULL);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_SUCCESS, status);

exit:
    status = cleanup_datastore(&datastore);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_SUCCESS, status);

    return test_status;
}

/**
 * @brief Verify that el2go_datastore_fs_create() rejects a NULL basename argument.
 *
 * Expects EL2GO_STATUS_INVALID_PARAMETER when basename is NULL.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_datastore_fs_null_basename(void *params)
{
    el2go_datastore_t datastore = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;

    (void)params;

    status = el2go_datastore_fs_create(&datastore, NULL);
    TEST_ASSERT_EQUAL(EL2GO_STATUS_INVALID_PARAMETER, status);

    return true;
}

/* ========================================================================== */
/* Test: Datastore Operations Boundary Conditions                             */
/* ========================================================================== */

/**
 * @brief Verify that the plain datastore accepts a write that fills the
 *        allocated buffer exactly and rejects any write starting at the
 *        end of the allocation.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_datastore_plain_exact_boundary_write(void *params)
{
    el2go_datastore_t datastore = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    uint8_t write_data[100] = { 0 };
    size_t bytes_written = 0;
    bool test_status = true;

    (void)params;

    status = el2go_datastore_plain_create(&datastore, NULL);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    if (!check_datastore(datastore))
        goto exit;

    status = datastore.ops->init(datastore.context, NULL);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    status = datastore.ops->allocate(datastore.context, 100);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    fill_buffer(write_data, sizeof(write_data), 0);

    status = datastore.ops->write(datastore.context, write_data, 0, 100, &bytes_written);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    TEST_ASSERT_EQUAL_GOTO(100, bytes_written, exit);

    status = datastore.ops->write(datastore.context, write_data, 100, 1, &bytes_written);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_BUFFER_TOO_SMALL, status, exit);
    TEST_ASSERT_EQUAL_CONTINUE(0, bytes_written);

exit:
    status = cleanup_datastore(&datastore);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_SUCCESS, status);

    return test_status;
}

/**
 * @brief Verify that the filesystem datastore handles writes at different
 *        offsets and that each region can subsequently be read back correctly.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_datastore_fs_seek_operations(void *params)
{
    el2go_datastore_t datastore = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    uint8_t write_data[32] = { 0 };
    uint8_t read_data[32] = { 0 };
    size_t bytes_written = 0;
    size_t bytes_read = 0;
    bool test_status = true;

    (void)params;

    status = el2go_datastore_fs_create(&datastore, __func__);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    if (!check_datastore(datastore))
        goto exit;

    status = datastore.ops->init(datastore.context, NULL);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    status = datastore.ops->allocate(datastore.context, 512);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    fill_buffer(write_data, sizeof(write_data), 0);

    status =
        datastore.ops->write(datastore.context, write_data, 0, sizeof(write_data), &bytes_written);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    TEST_ASSERT_EQUAL_GOTO(sizeof(write_data), bytes_written, exit);

    status = datastore.ops->write(datastore.context, write_data, 100, sizeof(write_data),
                                  &bytes_written);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    TEST_ASSERT_EQUAL_GOTO(sizeof(write_data), bytes_written, exit);

    status = datastore.ops->write(datastore.context, write_data, 200, sizeof(write_data),
                                  &bytes_written);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    TEST_ASSERT_EQUAL_GOTO(sizeof(write_data), bytes_written, exit);

    status = datastore.ops->commit(datastore.context);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    status = datastore.ops->read(datastore.context, read_data, 0, sizeof(read_data), &bytes_read);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    TEST_ASSERT_EQUAL_GOTO(sizeof(read_data), bytes_read, exit);

    TEST_ASSERT_MEMORY_EQUAL_GOTO(write_data, read_data, sizeof(write_data), exit);

    status = datastore.ops->read(datastore.context, read_data, 100, sizeof(read_data), &bytes_read);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    TEST_ASSERT_EQUAL_GOTO(sizeof(read_data), bytes_read, exit);

    TEST_ASSERT_MEMORY_EQUAL_GOTO(write_data, read_data, sizeof(write_data), exit);

    status = datastore.ops->read(datastore.context, read_data, 200, sizeof(read_data), &bytes_read);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    TEST_ASSERT_EQUAL_GOTO(sizeof(read_data), bytes_read, exit);

    TEST_ASSERT_MEMORY_EQUAL_CONTINUE(write_data, read_data, sizeof(write_data));

exit:
    status = cleanup_datastore(&datastore);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_SUCCESS, status);

    return test_status;
}

/* ========================================================================== */
/* Test: Datastore Error Recovery                                             */
/* ========================================================================== */

/**
 * @brief Verify that the plain datastore replaces a pending allocation when
 *        a new allocate is issued before the first transaction is committed.
 *
 * The first pending buffer must be discarded and the second write must succeed.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_datastore_plain_allocate_recovery(void *params)
{
    el2go_datastore_t datastore = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    uint8_t write_data[32] = { 0 };
    size_t bytes_written = 0;
    bool test_status = true;

    (void)params;

    status = el2go_datastore_plain_create(&datastore, NULL);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    if (!check_datastore(datastore))
        goto exit;

    status = datastore.ops->init(datastore.context, NULL);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    status = datastore.ops->allocate(datastore.context, 128);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    fill_buffer(write_data, sizeof(write_data), 0);

    status =
        datastore.ops->write(datastore.context, write_data, 0, sizeof(write_data), &bytes_written);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    TEST_ASSERT_EQUAL_GOTO(sizeof(write_data), bytes_written, exit);

    status = datastore.ops->allocate(datastore.context, 256);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    status =
        datastore.ops->write(datastore.context, write_data, 0, sizeof(write_data), &bytes_written);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    TEST_ASSERT_EQUAL_CONTINUE(sizeof(write_data), bytes_written);

exit:
    status = cleanup_datastore(&datastore);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_SUCCESS, status);

    return test_status;
}

/**
 * @brief Verify that the filesystem datastore replaces a pending file when
 *        a new allocate is issued before the first transaction is committed.
 *
 * The first pending file must be discarded and the second write must succeed.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_datastore_fs_file_recovery(void *params)
{
    el2go_datastore_t datastore = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    uint8_t write_data[32] = { 0 };
    size_t bytes_written = 0;
    bool test_status = true;

    (void)params;

    status = el2go_datastore_fs_create(&datastore, __func__);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    if (!check_datastore(datastore))
        goto exit;

    status = datastore.ops->init(datastore.context, NULL);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    status = datastore.ops->allocate(datastore.context, 128);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    fill_buffer(write_data, sizeof(write_data), 0);

    status =
        datastore.ops->write(datastore.context, write_data, 0, sizeof(write_data), &bytes_written);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    TEST_ASSERT_EQUAL_GOTO(sizeof(write_data), bytes_written, exit);

    status = datastore.ops->allocate(datastore.context, 256);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    status =
        datastore.ops->write(datastore.context, write_data, 0, sizeof(write_data), &bytes_written);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    TEST_ASSERT_EQUAL_CONTINUE(sizeof(write_data), bytes_written);

exit:
    status = cleanup_datastore(&datastore);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_SUCCESS, status);

    return test_status;
}

/* ========================================================================== */
/* Test: Datastore Memory Management                                          */
/* ========================================================================== */

/**
 * @brief Verify that the plain datastore handles multiple consecutive
 *        allocate/write/commit cycles with increasing allocation sizes
 *        without leaking memory or failing.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_datastore_plain_multiple_allocations(void *params)
{
    el2go_datastore_t datastore = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    uint8_t write_data[64] = { 0 };
    size_t bytes_written = 0;
    size_t i = 0;
    bool test_status = true;

    (void)params;

    status = el2go_datastore_plain_create(&datastore, NULL);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    if (!check_datastore(datastore))
        goto exit;

    status = datastore.ops->init(datastore.context, NULL);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    fill_buffer(write_data, sizeof(write_data), 0);

    for (; i < 10; i++) {
        status = datastore.ops->allocate(datastore.context, 128 * (i + 1));
        TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

        status = datastore.ops->write(datastore.context, write_data, 0, sizeof(write_data),
                                      &bytes_written);
        TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
        TEST_ASSERT_EQUAL_GOTO(sizeof(write_data), bytes_written, exit);

        status = datastore.ops->commit(datastore.context);
        TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    }

exit:
    status = cleanup_datastore(&datastore);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_SUCCESS, status);

    return test_status;
}

/**
 * @brief Verify that the filesystem datastore handles multiple consecutive
 *        allocate/write/commit cycles without errors, overwriting the
 *        backing file on each iteration.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_datastore_fs_multiple_files(void *params)
{
    el2go_datastore_t datastore = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    uint8_t write_data[64] = { 0 };
    size_t bytes_written = 0;
    size_t i = 0;
    bool test_status = true;

    (void)params;

    status = el2go_datastore_fs_create(&datastore, __func__);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    if (!check_datastore(datastore))
        goto exit;

    status = datastore.ops->init(datastore.context, NULL);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    fill_buffer(write_data, sizeof(write_data), 0);

    for (; i < 10; i++) {
        status = datastore.ops->allocate(datastore.context, 256);
        TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

        status = datastore.ops->write(datastore.context, write_data, 0, sizeof(write_data),
                                      &bytes_written);
        TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
        TEST_ASSERT_EQUAL_GOTO(sizeof(write_data), bytes_written, exit);

        status = datastore.ops->commit(datastore.context);
        TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    }

exit:
    status = cleanup_datastore(&datastore);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_SUCCESS, status);

    return test_status;
}

/* ========================================================================== */
/* Test: Datastore Data Integrity                                             */
/* ========================================================================== */

/**
 * @brief Verify data integrity for the plain datastore across multiple
 *        write segments covering the full allocated dataset.
 *
 * Writes several chunks at successive offsets, commits, then reads each
 * chunk back and verifies it matches the original data.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_datastore_plain_data_integrity(void *params)
{
    el2go_datastore_t datastore = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    uint8_t write_data[256] = { 0 };
    uint8_t read_data[256] = { 0 };
    size_t bytes_written = 0;
    size_t bytes_read = 0;
    bool test_status = true;

    (void)params;

    status = el2go_datastore_plain_create(&datastore, NULL);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    if (!check_datastore(datastore))
        goto exit;

    status = datastore.ops->init(datastore.context, NULL);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    status = datastore.ops->allocate(datastore.context, 512);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    fill_buffer(write_data, sizeof(write_data), 0);

    status = datastore.ops->write(datastore.context, write_data, 0, 64, &bytes_written);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    TEST_ASSERT_EQUAL_GOTO(64, bytes_written, exit);

    status = datastore.ops->write(datastore.context, write_data + 64, 64, 64, &bytes_written);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    TEST_ASSERT_EQUAL_GOTO(64, bytes_written, exit);

    status = datastore.ops->write(datastore.context, write_data + 128, 128, 64, &bytes_written);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    TEST_ASSERT_EQUAL_GOTO(64, bytes_written, exit);

    status = datastore.ops->write(datastore.context, write_data + 192, 192, 64, &bytes_written);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    TEST_ASSERT_EQUAL_GOTO(64, bytes_written, exit);

    status = datastore.ops->commit(datastore.context);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    status = datastore.ops->read(datastore.context, read_data, 0, 64, &bytes_read);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    TEST_ASSERT_EQUAL_GOTO(64, bytes_read, exit);

    TEST_ASSERT_MEMORY_EQUAL_GOTO(write_data, read_data, 64, exit);

    status = datastore.ops->read(datastore.context, read_data + 64, 64, 64, &bytes_read);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    TEST_ASSERT_EQUAL_GOTO(64, bytes_read, exit);

    TEST_ASSERT_MEMORY_EQUAL_GOTO(write_data + 64, read_data + 64, 64, exit);

    status = datastore.ops->read(datastore.context, read_data + 128, 128, 64, &bytes_read);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    TEST_ASSERT_EQUAL_GOTO(64, bytes_read, exit);

    TEST_ASSERT_MEMORY_EQUAL_GOTO(write_data + 128, read_data + 128, 64, exit);

    status = datastore.ops->read(datastore.context, read_data + 192, 192, 64, &bytes_read);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    TEST_ASSERT_EQUAL_GOTO(64, bytes_read, exit);

    TEST_ASSERT_MEMORY_EQUAL_CONTINUE(write_data + 192, read_data + 192, 64);

exit:
    status = cleanup_datastore(&datastore);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_SUCCESS, status);

    return test_status;
}

/**
 * @brief Verify data integrity for the filesystem datastore across multiple
 *        write segments covering the full allocated dataset.
 *
 * Writes several chunks at successive offsets, commits, then reads each
 * chunk back and verifies it matches the original data.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_datastore_fs_data_integrity(void *params)
{
    el2go_datastore_t datastore = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    uint8_t write_data[256] = { 0 };
    uint8_t read_data[256] = { 0 };
    size_t bytes_written = 0;
    size_t bytes_read = 0;
    bool test_status = true;

    (void)params;

    status = el2go_datastore_fs_create(&datastore, __func__);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    if (!check_datastore(datastore))
        goto exit;

    status = datastore.ops->init(datastore.context, NULL);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    status = datastore.ops->allocate(datastore.context, 512);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    fill_buffer(write_data, sizeof(write_data), 0);

    status = datastore.ops->write(datastore.context, write_data, 0, 64, &bytes_written);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    TEST_ASSERT_EQUAL_GOTO(64, bytes_written, exit);

    status = datastore.ops->write(datastore.context, write_data + 64, 64, 64, &bytes_written);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    TEST_ASSERT_EQUAL_GOTO(64, bytes_written, exit);

    status = datastore.ops->write(datastore.context, write_data + 128, 128, 64, &bytes_written);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    TEST_ASSERT_EQUAL_GOTO(64, bytes_written, exit);

    status = datastore.ops->write(datastore.context, write_data + 192, 192, 64, &bytes_written);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    TEST_ASSERT_EQUAL_GOTO(64, bytes_written, exit);

    status = datastore.ops->commit(datastore.context);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    status = datastore.ops->read(datastore.context, read_data, 0, 64, &bytes_read);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    TEST_ASSERT_EQUAL_GOTO(64, bytes_read, exit);

    TEST_ASSERT_MEMORY_EQUAL_GOTO(write_data, read_data, 64, exit);

    status = datastore.ops->read(datastore.context, read_data + 64, 64, 64, &bytes_read);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    TEST_ASSERT_EQUAL_GOTO(64, bytes_read, exit);

    TEST_ASSERT_MEMORY_EQUAL_GOTO(write_data + 64, read_data + 64, 64, exit);

    status = datastore.ops->read(datastore.context, read_data + 128, 128, 64, &bytes_read);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    TEST_ASSERT_EQUAL_GOTO(64, bytes_read, exit);

    TEST_ASSERT_MEMORY_EQUAL_GOTO(write_data + 128, read_data + 128, 64, exit);

    status = datastore.ops->read(datastore.context, read_data + 192, 192, 64, &bytes_read);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    TEST_ASSERT_EQUAL_GOTO(64, bytes_read, exit);

    TEST_ASSERT_MEMORY_EQUAL_CONTINUE(write_data + 192, read_data + 192, 64);

exit:
    status = cleanup_datastore(&datastore);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_SUCCESS, status);

    return test_status;
}

/* ========================================================================== */
/* Test: Datastore Stress Tests                                               */
/* ========================================================================== */

/**
 * @brief Stress-test the plain datastore by performing many allocate/write/commit/read
 *        iterations, each with a fresh pattern, verifying data integrity every round.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_datastore_plain_stress_test(void *params)
{
    el2go_datastore_t datastore = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    uint8_t write_data[128] = { 0 };
    uint8_t read_data[128] = { 0 };
    size_t bytes_written = 0;
    size_t bytes_read = 0;
    size_t i = 0;
    bool test_status = true;

    (void)params;

    status = el2go_datastore_plain_create(&datastore, NULL);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    if (!check_datastore(datastore))
        goto exit;

    status = datastore.ops->init(datastore.context, NULL);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    for (; i < 100; i++) {
        fill_buffer(write_data, sizeof(write_data), i);

        status = datastore.ops->allocate(datastore.context, 512);
        TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

        status = datastore.ops->write(datastore.context, write_data, 0, sizeof(write_data),
                                      &bytes_written);
        TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
        TEST_ASSERT_EQUAL_GOTO(sizeof(write_data), bytes_written, exit);

        status = datastore.ops->commit(datastore.context);
        TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

        status =
            datastore.ops->read(datastore.context, read_data, 0, sizeof(read_data), &bytes_read);
        TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
        TEST_ASSERT_EQUAL_GOTO(sizeof(read_data), bytes_read, exit);

        TEST_ASSERT_MEMORY_EQUAL_GOTO(write_data, read_data, sizeof(write_data), exit);
    }

exit:
    status = cleanup_datastore(&datastore);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_SUCCESS, status);

    return test_status;
}

/**
 * @brief Stress-test the filesystem datastore by performing many allocate/write/commit/read
 *        iterations, each with a fresh pattern, verifying data integrity every round.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_datastore_fs_stress_test(void *params)
{
    el2go_datastore_t datastore = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    uint8_t write_data[128] = { 0 };
    uint8_t read_data[128] = { 0 };
    size_t bytes_written = 0;
    size_t bytes_read = 0;
    size_t i = 0;
    bool test_status = true;

    (void)params;

    status = el2go_datastore_fs_create(&datastore, __func__);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    if (!check_datastore(datastore))
        goto exit;

    status = datastore.ops->init(datastore.context, NULL);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    for (; i < 50; i++) {
        fill_buffer(write_data, sizeof(write_data), i);

        status = datastore.ops->allocate(datastore.context, 512);
        TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

        status = datastore.ops->write(datastore.context, write_data, 0, sizeof(write_data),
                                      &bytes_written);
        TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
        TEST_ASSERT_EQUAL_GOTO(sizeof(write_data), bytes_written, exit);

        status = datastore.ops->commit(datastore.context);
        TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

        status =
            datastore.ops->read(datastore.context, read_data, 0, sizeof(read_data), &bytes_read);
        TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
        TEST_ASSERT_EQUAL_GOTO(sizeof(read_data), bytes_read, exit);

        TEST_ASSERT_MEMORY_EQUAL_GOTO(write_data, read_data, sizeof(write_data), exit);
    }

exit:
    status = cleanup_datastore(&datastore);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_SUCCESS, status);

    return test_status;
}

/* ========================================================================== */
/* Test: Datastore Operations with NULL Pointers                              */
/* ========================================================================== */

/**
 * @brief Verify that el2go_datastore_plain_create() rejects a NULL datastore pointer.
 *
 * Expects EL2GO_STATUS_INVALID_PARAMETER when the output datastore is NULL.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_datastore_plain_create_null_pointer(void *params)
{
    el2go_status_t status = EL2GO_STATUS_SUCCESS;

    (void)params;

    status = el2go_datastore_plain_create(NULL, NULL);
    TEST_ASSERT_EQUAL(EL2GO_STATUS_INVALID_PARAMETER, status);

    return true;
}

/**
 * @brief Verify that el2go_datastore_fs_create() rejects a NULL datastore pointer.
 *
 * Expects EL2GO_STATUS_INVALID_PARAMETER when the output datastore is NULL.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_datastore_fs_create_null_datastore(void *params)
{
    el2go_status_t status = EL2GO_STATUS_SUCCESS;

    (void)params;

    status = el2go_datastore_fs_create(NULL, __func__);
    TEST_ASSERT_EQUAL(EL2GO_STATUS_INVALID_PARAMETER, status);

    return true;
}

/* ========================================================================== */
/* Test: Datastore Index Overflow Protection                                  */
/* ========================================================================== */

/**
 * @brief Verify that the plain datastore correctly tracks allocated and
 *        committed buffers across multiple successive transactions.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_datastore_plain_index_management(void *params)
{
    el2go_datastore_t datastore = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    uint8_t write_data[32] = { 0 };
    uint8_t read_data[32] = { 0 };
    size_t bytes_written = 0;
    size_t bytes_read = 0;
    size_t i = 0;
    bool test_status = true;

    (void)params;

    status = el2go_datastore_plain_create(&datastore, NULL);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    if (!check_datastore(datastore))
        goto exit;

    status = datastore.ops->init(datastore.context, NULL);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    fill_buffer(write_data, sizeof(write_data), 0);

    for (; i < 10; i++) {
        status = datastore.ops->allocate(datastore.context, 128);
        TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

        status = datastore.ops->write(datastore.context, write_data, 0, sizeof(write_data),
                                      &bytes_written);
        TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
        TEST_ASSERT_EQUAL_GOTO(sizeof(write_data), bytes_written, exit);

        status = datastore.ops->commit(datastore.context);
        TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

        status =
            datastore.ops->read(datastore.context, read_data, 0, sizeof(read_data), &bytes_read);
        TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
        TEST_ASSERT_EQUAL_GOTO(sizeof(read_data), bytes_read, exit);

        TEST_ASSERT_MEMORY_EQUAL_GOTO(write_data, read_data, sizeof(write_data), exit);
    }

exit:
    status = cleanup_datastore(&datastore);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_SUCCESS, status);
    return test_status;
}

/**
 * @brief Verify that the filesystem datastore correctly overwrites and
 *        re-reads the backing file across multiple successive transactions.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_datastore_fs_index_management(void *params)
{
    el2go_datastore_t datastore = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    uint8_t write_data[32] = { 0 };
    uint8_t read_data[32] = { 0 };
    size_t bytes_written = 0;
    size_t bytes_read = 0;
    size_t i = 0;
    bool test_status = true;

    (void)params;

    status = el2go_datastore_fs_create(&datastore, __func__);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    if (!check_datastore(datastore))
        goto exit;

    status = datastore.ops->init(datastore.context, NULL);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    fill_buffer(write_data, sizeof(write_data), 0);

    for (; i < 10; i++) {
        status = datastore.ops->allocate(datastore.context, 128);
        TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

        status = datastore.ops->write(datastore.context, write_data, 0, sizeof(write_data),
                                      &bytes_written);
        TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
        TEST_ASSERT_EQUAL_GOTO(sizeof(write_data), bytes_written, exit);

        status = datastore.ops->commit(datastore.context);
        TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

        status =
            datastore.ops->read(datastore.context, read_data, 0, sizeof(read_data), &bytes_read);
        TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
        TEST_ASSERT_EQUAL_GOTO(sizeof(read_data), bytes_read, exit);

        TEST_ASSERT_MEMORY_EQUAL_GOTO(write_data, read_data, sizeof(write_data), exit);
    }

exit:
    status = cleanup_datastore(&datastore);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_SUCCESS, status);

    return test_status;
}

/* ========================================================================== */
/* Test: Partial Read/Write Operations                                        */
/* ========================================================================== */

/**
 * @brief Verify that the plain datastore reports EL2GO_STATUS_INCOMPLETE_WRITE when
 *        a write exceeds the allocation, and EL2GO_STATUS_INCOMPLETE_READ when a
 *        read exceeds the committed data, with correct byte counts in both cases.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_datastore_plain_partial_read_write(void *params)
{
    el2go_datastore_t datastore = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    uint8_t write_data[100] = { 0 };
    uint8_t read_data[150] = { 0 };
    size_t bytes_written = 0;
    size_t bytes_read = 0;
    bool test_status = true;

    (void)params;

    status = el2go_datastore_plain_create(&datastore, NULL);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    if (!check_datastore(datastore))
        goto exit;

    status = datastore.ops->init(datastore.context, NULL);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    /* Allocate 80 bytes */
    status = datastore.ops->allocate(datastore.context, 80);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    fill_buffer(write_data, sizeof(write_data), 0);

    /* Try to write 100 bytes - should only write 80 */
    status =
        datastore.ops->write(datastore.context, write_data, 0, sizeof(write_data), &bytes_written);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_INCOMPLETE_WRITE, status, exit);
    TEST_ASSERT_EQUAL_GOTO(bytes_written, 80, exit);

    status = datastore.ops->commit(datastore.context);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    /* Try to read 150 bytes - should only read 80 */
    status = datastore.ops->read(datastore.context, read_data, 0, sizeof(read_data), &bytes_read);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_INCOMPLETE_READ, status, exit);
    TEST_ASSERT_EQUAL_GOTO(bytes_read, 80, exit);

    /* Verify partial data is correct */
    TEST_ASSERT_MEMORY_EQUAL_CONTINUE(write_data, read_data, 80);

exit:
    status = cleanup_datastore(&datastore);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_SUCCESS, status);

    return test_status;
}

/**
 * @brief Verify that the filesystem datastore reports EL2GO_STATUS_INCOMPLETE_READ
 *        when a read request exceeds the committed file size.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_datastore_fs_partial_read_write(void *params)
{
    el2go_datastore_t datastore = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    uint8_t write_data[100] = { 0 };
    uint8_t read_data[150] = { 0 };
    size_t bytes_written = 0;
    size_t bytes_read = 0;
    bool test_status = true;

    (void)params;

    status = el2go_datastore_fs_create(&datastore, __func__);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    if (!check_datastore(datastore))
        goto exit;

    status = datastore.ops->init(datastore.context, NULL);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    /* Allocate space */
    status = datastore.ops->allocate(datastore.context, 256);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    fill_buffer(write_data, sizeof(write_data), 0);

    /* Write 100 bytes */
    status =
        datastore.ops->write(datastore.context, write_data, 0, sizeof(write_data), &bytes_written);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    TEST_ASSERT_EQUAL_GOTO(sizeof(write_data), bytes_written, exit);

    status = datastore.ops->commit(datastore.context);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    /* Try to read 150 bytes - should only read 100 (what was written) */
    status = datastore.ops->read(datastore.context, read_data, 0, sizeof(read_data), &bytes_read);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_INCOMPLETE_READ, status, exit);
    TEST_ASSERT_EQUAL_GOTO(bytes_read, 100, exit);

    /* Verify partial data is correct */
    TEST_ASSERT_MEMORY_EQUAL_CONTINUE(write_data, read_data, 100);

exit:
    status = cleanup_datastore(&datastore);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_SUCCESS, status);

    return test_status;
}

/* ========================================================================== */
/* Test: Bytes Read/Written NULL Pointer Tests                                */
/* ========================================================================== */

/**
 * @brief Verify that the plain datastore write and read ops reject a NULL bytes_written
 *        or bytes_read output pointer respectively.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_datastore_plain_null_bytes_pointers(void *params)
{
    el2go_datastore_t datastore = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    uint8_t data[32] = { 0 };
    bool test_status = true;

    (void)params;

    status = el2go_datastore_plain_create(&datastore, NULL);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    if (!check_datastore(datastore))
        goto exit;

    status = datastore.ops->init(datastore.context, NULL);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    status = datastore.ops->allocate(datastore.context, 128);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    /* Test write with NULL bytes_written */
    status = datastore.ops->write(datastore.context, data, 0, sizeof(data), NULL);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_INVALID_PARAMETER, status, exit);

    status = datastore.ops->commit(datastore.context);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    /* Test read with NULL bytes_read */
    status = datastore.ops->read(datastore.context, data, 0, sizeof(data), NULL);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_INVALID_PARAMETER, status);

exit:
    status = cleanup_datastore(&datastore);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_SUCCESS, status);

    return test_status;
}

/**
 * @brief Verify that the filesystem datastore write and read ops reject a NULL
 *        bytes_written or bytes_read output pointer respectively.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_datastore_fs_null_bytes_pointers(void *params)
{
    el2go_datastore_t datastore = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    uint8_t data[32] = { 0 };
    bool test_status = true;

    (void)params;

    status = el2go_datastore_fs_create(&datastore, __func__);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    if (!check_datastore(datastore))
        goto exit;

    status = datastore.ops->init(datastore.context, NULL);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    status = datastore.ops->allocate(datastore.context, 128);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    /* Test write with NULL bytes_written */
    status = datastore.ops->write(datastore.context, data, 0, sizeof(data), NULL);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_INVALID_PARAMETER, status, exit);

    status = datastore.ops->commit(datastore.context);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    /* Test read with NULL bytes_read */
    status = datastore.ops->read(datastore.context, data, 0, sizeof(data), NULL);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_INVALID_PARAMETER, status);

exit:
    status = cleanup_datastore(&datastore);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_SUCCESS, status);

    return test_status;
}

/* ========================================================================== */
/* Test: Edge Cases for Offset Operations                                     */
/* ========================================================================== */

/**
 * @brief Verify that the plain datastore handles writes and reads that land exactly
 *        at the buffer boundary, and correctly truncates writes that extend past it.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_datastore_plain_offset_at_boundary(void *params)
{
    el2go_datastore_t datastore = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    uint8_t write_data[32] = { 0 };
    uint8_t read_data[32] = { 0 };
    size_t bytes_written = 0;
    size_t bytes_read = 0;
    bool test_status = true;

    (void)params;

    status = el2go_datastore_plain_create(&datastore, NULL);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    if (!check_datastore(datastore))
        goto exit;

    status = datastore.ops->init(datastore.context, NULL);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    status = datastore.ops->allocate(datastore.context, 100);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    fill_buffer(write_data, sizeof(write_data), 0);

    /* Write at offset 68 (100 - 32 = 68, so this should fit exactly) */
    status =
        datastore.ops->write(datastore.context, write_data, 68, sizeof(write_data), &bytes_written);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    TEST_ASSERT_EQUAL_GOTO(sizeof(write_data), bytes_written, exit);

    status = datastore.ops->commit(datastore.context);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    /* Read from the same offset */
    status = datastore.ops->read(datastore.context, read_data, 68, sizeof(read_data), &bytes_read);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    TEST_ASSERT_EQUAL_GOTO(sizeof(read_data), bytes_read, exit);

    TEST_ASSERT_MEMORY_EQUAL_GOTO(write_data, read_data, sizeof(write_data), exit);

    /* Try to write at offset 69 (should partially fail) */
    bytes_written = 0;
    status = datastore.ops->allocate(datastore.context, 100);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    status =
        datastore.ops->write(datastore.context, write_data, 69, sizeof(write_data), &bytes_written);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_INCOMPLETE_WRITE, status, exit);
    TEST_ASSERT_EQUAL_CONTINUE(bytes_written, 31);

exit:
    status = cleanup_datastore(&datastore);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_SUCCESS, status);

    return test_status;
}

/**
 * @brief Verify that the filesystem datastore correctly reads back data written at
 *        a non-zero offset within the allocated file.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_datastore_fs_offset_at_boundary(void *params)
{
    el2go_datastore_t datastore = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    uint8_t write_data[32] = { 0 };
    uint8_t read_data[32] = { 0 };
    size_t bytes_written = 0;
    size_t bytes_read = 0;
    bool test_status = true;

    (void)params;

    status = el2go_datastore_fs_create(&datastore, __func__);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    if (!check_datastore(datastore))
        goto exit;

    status = datastore.ops->init(datastore.context, NULL);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    status = datastore.ops->allocate(datastore.context, 256);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    fill_buffer(write_data, sizeof(write_data), 0);

    /* Write at offset 100 */
    status = datastore.ops->write(datastore.context, write_data, 100, sizeof(write_data),
                                  &bytes_written);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    TEST_ASSERT_EQUAL_GOTO(sizeof(write_data), bytes_written, exit);

    status = datastore.ops->commit(datastore.context);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    /* Read from the same offset */
    status = datastore.ops->read(datastore.context, read_data, 100, sizeof(read_data), &bytes_read);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    TEST_ASSERT_EQUAL_GOTO(sizeof(read_data), bytes_read, exit);

    TEST_ASSERT_MEMORY_EQUAL_CONTINUE(write_data, read_data, sizeof(write_data));

exit:
    status = cleanup_datastore(&datastore);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_SUCCESS, status);

    return test_status;
}

/* ========================================================================== */
/* Test: Zero Bytes Read/Written Scenarios                                    */
/* ========================================================================== */

/**
 * @brief Verify that reading from an offset equal to the committed data size returns
 *        EL2GO_STATUS_BUFFER_TOO_SMALL for the plain datastore.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_datastore_plain_read_at_end(void *params)
{
    el2go_datastore_t datastore = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    uint8_t write_data[50] = { 0 };
    uint8_t read_data[10] = { 0 };
    size_t bytes_written = 0;
    size_t bytes_read = 0;
    bool test_status = true;

    (void)params;

    status = el2go_datastore_plain_create(&datastore, NULL);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    if (!check_datastore(datastore))
        goto exit;

    status = datastore.ops->init(datastore.context, NULL);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    status = datastore.ops->allocate(datastore.context, 50);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    fill_buffer(write_data, sizeof(write_data), 0);

    status =
        datastore.ops->write(datastore.context, write_data, 0, sizeof(write_data), &bytes_written);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    TEST_ASSERT_EQUAL_GOTO(sizeof(write_data), bytes_written, exit);

    status = datastore.ops->commit(datastore.context);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    /* Try to read at offset 50 (exactly at the end) */
    status = datastore.ops->read(datastore.context, read_data, 50, sizeof(read_data), &bytes_read);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_BUFFER_TOO_SMALL, status, exit);
    TEST_ASSERT_EQUAL_CONTINUE(bytes_read, 0);

exit:
    status = cleanup_datastore(&datastore);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_SUCCESS, status);

    return test_status;
}

/**
 * @brief Verify that writing at an offset equal to the allocated size returns
 *        EL2GO_STATUS_BUFFER_TOO_SMALL for the plain datastore.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_datastore_plain_write_at_end(void *params)
{
    el2go_datastore_t datastore = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    uint8_t write_data[10] = { 0 };
    size_t bytes_written = 0;
    bool test_status = true;

    (void)params;

    status = el2go_datastore_plain_create(&datastore, NULL);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    if (!check_datastore(datastore))
        goto exit;

    status = datastore.ops->init(datastore.context, NULL);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    status = datastore.ops->allocate(datastore.context, 50);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    fill_buffer(write_data, sizeof(write_data), 0);

    /* Try to write at offset 50 (exactly at the end) */
    status =
        datastore.ops->write(datastore.context, write_data, 50, sizeof(write_data), &bytes_written);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_BUFFER_TOO_SMALL, status, exit);
    TEST_ASSERT_EQUAL_CONTINUE(bytes_written, 0);

exit:
    status = cleanup_datastore(&datastore);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_SUCCESS, status);

    return test_status;
}

/* ========================================================================== */
/* Test Registration                                                          */
/* ========================================================================== */

/**
 * @brief Register all internal datastore tests with the test framework.
 *
 * @param[in] include_fs_tests If true, filesystem-backed datastore tests are included.
 */
void register_datastore_tests(bool include_fs_tests)
{
    /* Set suite-level setup function */
    TEST_SET_SUITE_SETUP(suite_setup);

    /* Plain datastore internal tests */
    TEST_REGISTER(test_datastore_plain_context_structure);
    TEST_REGISTER(test_datastore_plain_buffer_switching);
    TEST_REGISTER(test_datastore_plain_null_context);
    TEST_REGISTER(test_datastore_plain_create_null_pointer);

    /* FS datastore internal tests */
    TEST_REGISTER(test_datastore_fs_context_structure);
    TEST_REGISTER(test_datastore_fs_file_switching);
    TEST_REGISTER(test_datastore_fs_null_context);
    TEST_REGISTER(test_datastore_fs_null_basename);
    TEST_REGISTER(test_datastore_fs_create_null_datastore);

    /* Boundary condition tests */
    TEST_REGISTER(test_datastore_plain_exact_boundary_write);
    TEST_REGISTER(test_datastore_fs_seek_operations);

    /* Error recovery tests */
    TEST_REGISTER(test_datastore_plain_allocate_recovery);
    TEST_REGISTER(test_datastore_fs_file_recovery);

    /* Memory management tests */
    TEST_REGISTER(test_datastore_plain_multiple_allocations);
    TEST_REGISTER(test_datastore_fs_multiple_files);

    /* Data integrity tests */
    TEST_REGISTER(test_datastore_plain_data_integrity);
    TEST_REGISTER(test_datastore_fs_data_integrity);

    /* Stress tests */
    TEST_REGISTER(test_datastore_plain_stress_test);
    TEST_REGISTER(test_datastore_fs_stress_test);

    /* Index management tests */
    TEST_REGISTER(test_datastore_plain_index_management);
    TEST_REGISTER(test_datastore_fs_index_management);

    /* Partial read/write tests */
    TEST_REGISTER(test_datastore_plain_partial_read_write);
    TEST_REGISTER(test_datastore_fs_partial_read_write);

    /* NULL bytes pointer tests */
    TEST_REGISTER(test_datastore_plain_null_bytes_pointers);
    TEST_REGISTER(test_datastore_fs_null_bytes_pointers);

    /* Offset boundary tests */
    TEST_REGISTER(test_datastore_plain_offset_at_boundary);
    TEST_REGISTER(test_datastore_fs_offset_at_boundary);

    /* Zero bytes scenarios */
    TEST_REGISTER(test_datastore_plain_read_at_end);
    TEST_REGISTER(test_datastore_plain_write_at_end);

    /* handle_request tests (in test_el2go_datastore_handle_request.c) */
    register_datastore_handle_request_tests(include_fs_tests);

    /* get_size tests (in test_el2go_datastore_get_size.c) */
    register_datastore_get_size_tests(include_fs_tests);
}
