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
    if (!datastore)
        return EL2GO_STATUS_INVALID_POINTER;

    if (datastore->context) {
        if (datastore->ops && datastore->ops->free) {
            el2go_status_t status = datastore->ops->free(datastore->context);
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

static bool test_datastore_plain_context_structure(void *params)
{
    el2go_datastore_t datastore = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    bool test_status = true;

    (void)params;

    status = el2go_datastore_plain_create(&datastore, NULL);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    if (!check_datastore(datastore))
        goto exit;

    status = datastore.ops->init(datastore.context, NULL);
    TEST_ASSERT_EQUAL_CONTINUE(status, EL2GO_STATUS_SUCCESS);

exit:
    status = cleanup_datastore(&datastore);
    TEST_ASSERT_EQUAL_CONTINUE(status, EL2GO_STATUS_SUCCESS);

    return test_status;
}

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
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    if (!check_datastore(datastore))
        goto exit;

    status = datastore.ops->init(datastore.context, NULL);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    status = datastore.ops->allocate(datastore.context, 128);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    fill_buffer(write_data1, sizeof(write_data1), 0);

    status = datastore.ops->write(datastore.context, write_data1, 0, sizeof(write_data1),
                                  &bytes_written);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);
    TEST_ASSERT_EQUAL_GOTO(bytes_written, sizeof(write_data1), exit);

    status = datastore.ops->commit(datastore.context);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    status = datastore.ops->allocate(datastore.context, 128);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    fill_buffer(write_data2, sizeof(write_data2), 100);

    status = datastore.ops->write(datastore.context, write_data2, 0, sizeof(write_data2),
                                  &bytes_written);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);
    TEST_ASSERT_EQUAL_GOTO(bytes_written, sizeof(write_data2), exit);

    status = datastore.ops->commit(datastore.context);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    status = datastore.ops->read(datastore.context, read_data, 0, sizeof(read_data), &bytes_read);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);
    TEST_ASSERT_EQUAL_GOTO(bytes_read, sizeof(read_data), exit);

    TEST_ASSERT_MEMORY_EQUAL_CONTINUE(write_data2, read_data, sizeof(write_data2));

exit:
    status = cleanup_datastore(&datastore);
    TEST_ASSERT_EQUAL_CONTINUE(status, EL2GO_STATUS_SUCCESS);

    return test_status;
}

static bool test_datastore_plain_null_context(void *params)
{
    el2go_datastore_t datastore = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    uint8_t data[32] = { 0 };
    size_t bytes = 0;
    bool test_status = true;

    (void)params;

    status = el2go_datastore_plain_create(&datastore, NULL);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    if (!check_datastore(datastore))
        goto exit;

    status = datastore.ops->init(NULL, NULL);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_INVALID_PARAMETER, exit);

    status = datastore.ops->allocate(NULL, 128);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_INVALID_PARAMETER, exit);

    status = datastore.ops->read(NULL, data, 0, 32, &bytes);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_INVALID_PARAMETER, exit);

    status = datastore.ops->write(NULL, data, 0, 32, &bytes);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_INVALID_PARAMETER, exit);

    status = datastore.ops->commit(NULL);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_INVALID_PARAMETER, exit);

    status = datastore.ops->free(NULL);
    TEST_ASSERT_EQUAL_CONTINUE(status, EL2GO_STATUS_SUCCESS);

exit:
    status = cleanup_datastore(&datastore);
    TEST_ASSERT_EQUAL_CONTINUE(status, EL2GO_STATUS_SUCCESS);

    return test_status;
}

/* ========================================================================== */
/* Test: FS Datastore Internal Structure                                      */
/* ========================================================================== */

static bool test_datastore_fs_context_structure(void *params)
{
    el2go_datastore_t datastore = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    bool test_status = true;

    (void)params;

    status = el2go_datastore_fs_create(&datastore, __func__);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    if (!check_datastore(datastore))
        goto exit;

    status = datastore.ops->init(datastore.context, NULL);
    TEST_ASSERT_EQUAL_CONTINUE(status, EL2GO_STATUS_SUCCESS);

exit:
    status = cleanup_datastore(&datastore);
    TEST_ASSERT_EQUAL_CONTINUE(status, EL2GO_STATUS_SUCCESS);

    return test_status;
}

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
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    if (!check_datastore(datastore))
        goto exit;

    status = datastore.ops->init(datastore.context, NULL);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    status = datastore.ops->allocate(datastore.context, 256);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    fill_buffer(write_data1, sizeof(write_data1), 0);

    status = datastore.ops->write(datastore.context, write_data1, 0, sizeof(write_data1),
                                  &bytes_written);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);
    TEST_ASSERT_EQUAL_GOTO(bytes_written, sizeof(write_data1), exit);

    status = datastore.ops->commit(datastore.context);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    status = datastore.ops->allocate(datastore.context, 256);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    fill_buffer(write_data2, sizeof(write_data2), 50);

    status = datastore.ops->write(datastore.context, write_data2, 0, sizeof(write_data2),
                                  &bytes_written);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);
    TEST_ASSERT_EQUAL_GOTO(bytes_written, sizeof(write_data2), exit);

    status = datastore.ops->commit(datastore.context);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    status = datastore.ops->read(datastore.context, read_data, 0, sizeof(read_data), &bytes_read);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);
    TEST_ASSERT_EQUAL_GOTO(bytes_read, sizeof(read_data), exit);

    TEST_ASSERT_MEMORY_EQUAL_CONTINUE(write_data2, read_data, sizeof(write_data2));

exit:
    status = cleanup_datastore(&datastore);
    TEST_ASSERT_EQUAL_CONTINUE(status, EL2GO_STATUS_SUCCESS);

    return test_status;
}

static bool test_datastore_fs_null_context(void *params)
{
    el2go_datastore_t datastore = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    uint8_t data[32] = { 0 };
    size_t bytes = 0;
    bool test_status = true;

    (void)params;

    status = el2go_datastore_fs_create(&datastore, __func__);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    if (!check_datastore(datastore))
        goto exit;

    status = datastore.ops->init(NULL, NULL);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_INVALID_PARAMETER, exit);

    status = datastore.ops->allocate(NULL, 128);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_INVALID_PARAMETER, exit);

    status = datastore.ops->read(NULL, data, 0, 32, &bytes);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_INVALID_PARAMETER, exit);

    status = datastore.ops->write(NULL, data, 0, 32, &bytes);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_INVALID_PARAMETER, exit);

    status = datastore.ops->commit(NULL);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_INVALID_PARAMETER, exit);

    status = datastore.ops->free(NULL);
    TEST_ASSERT_EQUAL_CONTINUE(status, EL2GO_STATUS_SUCCESS);

exit:
    status = cleanup_datastore(&datastore);
    TEST_ASSERT_EQUAL_CONTINUE(status, EL2GO_STATUS_SUCCESS);

    return test_status;
}

static bool test_datastore_fs_null_basename(void *params)
{
    el2go_datastore_t datastore = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;

    (void)params;

    status = el2go_datastore_fs_create(&datastore, NULL);
    TEST_ASSERT_EQUAL(status, EL2GO_STATUS_INVALID_PARAMETER);

    return true;
}

/* ========================================================================== */
/* Test: Datastore Operations Boundary Conditions                             */
/* ========================================================================== */

static bool test_datastore_plain_exact_boundary_write(void *params)
{
    el2go_datastore_t datastore = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    uint8_t write_data[100] = { 0 };
    size_t bytes_written = 0;
    bool test_status = true;

    (void)params;

    status = el2go_datastore_plain_create(&datastore, NULL);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    if (!check_datastore(datastore))
        goto exit;

    status = datastore.ops->init(datastore.context, NULL);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    status = datastore.ops->allocate(datastore.context, 100);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    fill_buffer(write_data, sizeof(write_data), 0);

    status = datastore.ops->write(datastore.context, write_data, 0, 100, &bytes_written);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);
    TEST_ASSERT_EQUAL_GOTO(bytes_written, 100, exit);

    status = datastore.ops->write(datastore.context, write_data, 100, 1, &bytes_written);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_BUFFER_TOO_SMALL, exit);
    TEST_ASSERT_EQUAL_CONTINUE(bytes_written, 0);

exit:
    status = cleanup_datastore(&datastore);
    TEST_ASSERT_EQUAL_CONTINUE(status, EL2GO_STATUS_SUCCESS);

    return test_status;
}

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
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    if (!check_datastore(datastore))
        goto exit;

    status = datastore.ops->init(datastore.context, NULL);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    status = datastore.ops->allocate(datastore.context, 512);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    fill_buffer(write_data, sizeof(write_data), 0);

    status =
        datastore.ops->write(datastore.context, write_data, 0, sizeof(write_data), &bytes_written);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);
    TEST_ASSERT_EQUAL_GOTO(bytes_written, sizeof(write_data), exit);

    status = datastore.ops->write(datastore.context, write_data, 100, sizeof(write_data),
                                  &bytes_written);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);
    TEST_ASSERT_EQUAL_GOTO(bytes_written, sizeof(write_data), exit);

    status = datastore.ops->write(datastore.context, write_data, 200, sizeof(write_data),
                                  &bytes_written);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);
    TEST_ASSERT_EQUAL_GOTO(bytes_written, sizeof(write_data), exit);

    status = datastore.ops->commit(datastore.context);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    status = datastore.ops->read(datastore.context, read_data, 0, sizeof(read_data), &bytes_read);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);
    TEST_ASSERT_EQUAL_GOTO(bytes_read, sizeof(read_data), exit);

    TEST_ASSERT_MEMORY_EQUAL_GOTO(write_data, read_data, sizeof(write_data), exit);

    status = datastore.ops->read(datastore.context, read_data, 100, sizeof(read_data), &bytes_read);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);
    TEST_ASSERT_EQUAL_GOTO(bytes_read, sizeof(read_data), exit);

    TEST_ASSERT_MEMORY_EQUAL_GOTO(write_data, read_data, sizeof(write_data), exit);

    status = datastore.ops->read(datastore.context, read_data, 200, sizeof(read_data), &bytes_read);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);
    TEST_ASSERT_EQUAL_GOTO(bytes_read, sizeof(read_data), exit);

    TEST_ASSERT_MEMORY_EQUAL_CONTINUE(write_data, read_data, sizeof(write_data));

exit:
    status = cleanup_datastore(&datastore);
    TEST_ASSERT_EQUAL_CONTINUE(status, EL2GO_STATUS_SUCCESS);

    return test_status;
}

/* ========================================================================== */
/* Test: Datastore Error Recovery                                             */
/* ========================================================================== */

static bool test_datastore_plain_allocate_recovery(void *params)
{
    el2go_datastore_t datastore = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    uint8_t write_data[32] = { 0 };
    size_t bytes_written = 0;
    bool test_status = true;

    (void)params;

    status = el2go_datastore_plain_create(&datastore, NULL);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    if (!check_datastore(datastore))
        goto exit;

    status = datastore.ops->init(datastore.context, NULL);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    status = datastore.ops->allocate(datastore.context, 128);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    fill_buffer(write_data, sizeof(write_data), 0);

    status =
        datastore.ops->write(datastore.context, write_data, 0, sizeof(write_data), &bytes_written);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);
    TEST_ASSERT_EQUAL_GOTO(bytes_written, sizeof(write_data), exit);

    status = datastore.ops->allocate(datastore.context, 256);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    status =
        datastore.ops->write(datastore.context, write_data, 0, sizeof(write_data), &bytes_written);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);
    TEST_ASSERT_EQUAL_CONTINUE(bytes_written, sizeof(write_data));

exit:
    status = cleanup_datastore(&datastore);
    TEST_ASSERT_EQUAL_CONTINUE(status, EL2GO_STATUS_SUCCESS);

    return test_status;
}

static bool test_datastore_fs_file_recovery(void *params)
{
    el2go_datastore_t datastore = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    uint8_t write_data[32] = { 0 };
    size_t bytes_written = 0;
    bool test_status = true;

    (void)params;

    status = el2go_datastore_fs_create(&datastore, __func__);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    if (!check_datastore(datastore))
        goto exit;

    status = datastore.ops->init(datastore.context, NULL);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    status = datastore.ops->allocate(datastore.context, 128);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    fill_buffer(write_data, sizeof(write_data), 0);

    status =
        datastore.ops->write(datastore.context, write_data, 0, sizeof(write_data), &bytes_written);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);
    TEST_ASSERT_EQUAL_GOTO(bytes_written, sizeof(write_data), exit);

    status = datastore.ops->allocate(datastore.context, 256);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    status =
        datastore.ops->write(datastore.context, write_data, 0, sizeof(write_data), &bytes_written);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);
    TEST_ASSERT_EQUAL_CONTINUE(bytes_written, sizeof(write_data));

exit:
    status = cleanup_datastore(&datastore);
    TEST_ASSERT_EQUAL_CONTINUE(status, EL2GO_STATUS_SUCCESS);

    return test_status;
}

/* ========================================================================== */
/* Test: Datastore Memory Management                                          */
/* ========================================================================== */

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
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    if (!check_datastore(datastore))
        goto exit;

    status = datastore.ops->init(datastore.context, NULL);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    fill_buffer(write_data, sizeof(write_data), 0);

    for (; i < 10; i++) {
        status = datastore.ops->allocate(datastore.context, 128 * (i + 1));
        TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

        status = datastore.ops->write(datastore.context, write_data, 0, sizeof(write_data),
                                      &bytes_written);
        TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);
        TEST_ASSERT_EQUAL_GOTO(bytes_written, sizeof(write_data), exit);

        status = datastore.ops->commit(datastore.context);
        TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);
    }

exit:
    status = cleanup_datastore(&datastore);
    TEST_ASSERT_EQUAL_CONTINUE(status, EL2GO_STATUS_SUCCESS);

    return test_status;
}

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
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    if (!check_datastore(datastore))
        goto exit;

    status = datastore.ops->init(datastore.context, NULL);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    fill_buffer(write_data, sizeof(write_data), 0);

    for (; i < 10; i++) {
        status = datastore.ops->allocate(datastore.context, 256);
        TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

        status = datastore.ops->write(datastore.context, write_data, 0, sizeof(write_data),
                                      &bytes_written);
        TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);
        TEST_ASSERT_EQUAL_GOTO(bytes_written, sizeof(write_data), exit);

        status = datastore.ops->commit(datastore.context);
        TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);
    }

exit:
    status = cleanup_datastore(&datastore);
    TEST_ASSERT_EQUAL_CONTINUE(status, EL2GO_STATUS_SUCCESS);

    return test_status;
}

/* ========================================================================== */
/* Test: Datastore Data Integrity                                             */
/* ========================================================================== */

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
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    if (!check_datastore(datastore))
        goto exit;

    status = datastore.ops->init(datastore.context, NULL);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    status = datastore.ops->allocate(datastore.context, 512);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    fill_buffer(write_data, sizeof(write_data), 0);

    status = datastore.ops->write(datastore.context, write_data, 0, 64, &bytes_written);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);
    TEST_ASSERT_EQUAL_GOTO(bytes_written, 64, exit);

    status = datastore.ops->write(datastore.context, write_data + 64, 64, 64, &bytes_written);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);
    TEST_ASSERT_EQUAL_GOTO(bytes_written, 64, exit);

    status = datastore.ops->write(datastore.context, write_data + 128, 128, 64, &bytes_written);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);
    TEST_ASSERT_EQUAL_GOTO(bytes_written, 64, exit);

    status = datastore.ops->write(datastore.context, write_data + 192, 192, 64, &bytes_written);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);
    TEST_ASSERT_EQUAL_GOTO(bytes_written, 64, exit);

    status = datastore.ops->commit(datastore.context);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    status = datastore.ops->read(datastore.context, read_data, 0, 64, &bytes_read);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);
    TEST_ASSERT_EQUAL_GOTO(bytes_read, 64, exit);

    TEST_ASSERT_MEMORY_EQUAL_GOTO(write_data, read_data, 64, exit);

    status = datastore.ops->read(datastore.context, read_data + 64, 64, 64, &bytes_read);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);
    TEST_ASSERT_EQUAL_GOTO(bytes_read, 64, exit);

    TEST_ASSERT_MEMORY_EQUAL_GOTO(write_data + 64, read_data + 64, 64, exit);

    status = datastore.ops->read(datastore.context, read_data + 128, 128, 64, &bytes_read);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);
    TEST_ASSERT_EQUAL_GOTO(bytes_read, 64, exit);

    TEST_ASSERT_MEMORY_EQUAL_GOTO(write_data + 128, read_data + 128, 64, exit);

    status = datastore.ops->read(datastore.context, read_data + 192, 192, 64, &bytes_read);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);
    TEST_ASSERT_EQUAL_GOTO(bytes_read, 64, exit);

    TEST_ASSERT_MEMORY_EQUAL_CONTINUE(write_data + 192, read_data + 192, 64);

exit:
    status = cleanup_datastore(&datastore);
    TEST_ASSERT_EQUAL_CONTINUE(status, EL2GO_STATUS_SUCCESS);

    return test_status;
}

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
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    if (!check_datastore(datastore))
        goto exit;

    status = datastore.ops->init(datastore.context, NULL);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    status = datastore.ops->allocate(datastore.context, 512);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    fill_buffer(write_data, sizeof(write_data), 0);

    status = datastore.ops->write(datastore.context, write_data, 0, 64, &bytes_written);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);
    TEST_ASSERT_EQUAL_GOTO(bytes_written, 64, exit);

    status = datastore.ops->write(datastore.context, write_data + 64, 64, 64, &bytes_written);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);
    TEST_ASSERT_EQUAL_GOTO(bytes_written, 64, exit);

    status = datastore.ops->write(datastore.context, write_data + 128, 128, 64, &bytes_written);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);
    TEST_ASSERT_EQUAL_GOTO(bytes_written, 64, exit);

    status = datastore.ops->write(datastore.context, write_data + 192, 192, 64, &bytes_written);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);
    TEST_ASSERT_EQUAL_GOTO(bytes_written, 64, exit);

    status = datastore.ops->commit(datastore.context);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    status = datastore.ops->read(datastore.context, read_data, 0, 64, &bytes_read);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);
    TEST_ASSERT_EQUAL_GOTO(bytes_read, 64, exit);

    TEST_ASSERT_MEMORY_EQUAL_GOTO(write_data, read_data, 64, exit);

    status = datastore.ops->read(datastore.context, read_data + 64, 64, 64, &bytes_read);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);
    TEST_ASSERT_EQUAL_GOTO(bytes_read, 64, exit);

    TEST_ASSERT_MEMORY_EQUAL_GOTO(write_data + 64, read_data + 64, 64, exit);

    status = datastore.ops->read(datastore.context, read_data + 128, 128, 64, &bytes_read);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);
    TEST_ASSERT_EQUAL_GOTO(bytes_read, 64, exit);

    TEST_ASSERT_MEMORY_EQUAL_GOTO(write_data + 128, read_data + 128, 64, exit);

    status = datastore.ops->read(datastore.context, read_data + 192, 192, 64, &bytes_read);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);
    TEST_ASSERT_EQUAL_GOTO(bytes_read, 64, exit);

    TEST_ASSERT_MEMORY_EQUAL_CONTINUE(write_data + 192, read_data + 192, 64);

exit:
    status = cleanup_datastore(&datastore);
    TEST_ASSERT_EQUAL_CONTINUE(status, EL2GO_STATUS_SUCCESS);

    return test_status;
}

/* ========================================================================== */
/* Test: Datastore Stress Tests                                               */
/* ========================================================================== */

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
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    if (!check_datastore(datastore))
        goto exit;

    status = datastore.ops->init(datastore.context, NULL);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    for (; i < 100; i++) {
        fill_buffer(write_data, sizeof(write_data), i);

        status = datastore.ops->allocate(datastore.context, 512);
        TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

        status = datastore.ops->write(datastore.context, write_data, 0, sizeof(write_data),
                                      &bytes_written);
        TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);
        TEST_ASSERT_EQUAL_GOTO(bytes_written, sizeof(write_data), exit);

        status = datastore.ops->commit(datastore.context);
        TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

        status =
            datastore.ops->read(datastore.context, read_data, 0, sizeof(read_data), &bytes_read);
        TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);
        TEST_ASSERT_EQUAL_GOTO(bytes_read, sizeof(read_data), exit);

        TEST_ASSERT_MEMORY_EQUAL_GOTO(write_data, read_data, sizeof(write_data), exit);
    }

exit:
    status = cleanup_datastore(&datastore);
    TEST_ASSERT_EQUAL_CONTINUE(status, EL2GO_STATUS_SUCCESS);

    return test_status;
}

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
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    if (!check_datastore(datastore))
        goto exit;

    status = datastore.ops->init(datastore.context, NULL);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    for (; i < 50; i++) {
        fill_buffer(write_data, sizeof(write_data), i);

        status = datastore.ops->allocate(datastore.context, 512);
        TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

        status = datastore.ops->write(datastore.context, write_data, 0, sizeof(write_data),
                                      &bytes_written);
        TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);
        TEST_ASSERT_EQUAL_GOTO(bytes_written, sizeof(write_data), exit);

        status = datastore.ops->commit(datastore.context);
        TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

        status =
            datastore.ops->read(datastore.context, read_data, 0, sizeof(read_data), &bytes_read);
        TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);
        TEST_ASSERT_EQUAL_GOTO(bytes_read, sizeof(read_data), exit);

        TEST_ASSERT_MEMORY_EQUAL_GOTO(write_data, read_data, sizeof(write_data), exit);
    }

exit:
    status = cleanup_datastore(&datastore);
    TEST_ASSERT_EQUAL_CONTINUE(status, EL2GO_STATUS_SUCCESS);

    return test_status;
}

/* ========================================================================== */
/* Test: Datastore Operations with NULL Pointers                              */
/* ========================================================================== */

static bool test_datastore_plain_create_null_pointer(void *params)
{
    el2go_status_t status = EL2GO_STATUS_SUCCESS;

    (void)params;

    status = el2go_datastore_plain_create(NULL, NULL);
    TEST_ASSERT_EQUAL(status, EL2GO_STATUS_INVALID_PARAMETER);

    return true;
}

static bool test_datastore_fs_create_null_datastore(void *params)
{
    el2go_status_t status = EL2GO_STATUS_SUCCESS;

    (void)params;

    status = el2go_datastore_fs_create(NULL, __func__);
    TEST_ASSERT_EQUAL(status, EL2GO_STATUS_INVALID_PARAMETER);

    return true;
}

/* ========================================================================== */
/* Test: Datastore Index Overflow Protection                                  */
/* ========================================================================== */

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
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    if (!check_datastore(datastore))
        goto exit;

    status = datastore.ops->init(datastore.context, NULL);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    fill_buffer(write_data, sizeof(write_data), 0);

    for (; i < 10; i++) {
        status = datastore.ops->allocate(datastore.context, 128);
        TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

        status = datastore.ops->write(datastore.context, write_data, 0, sizeof(write_data),
                                      &bytes_written);
        TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);
        TEST_ASSERT_EQUAL_GOTO(bytes_written, sizeof(write_data), exit);

        status = datastore.ops->commit(datastore.context);
        TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

        status =
            datastore.ops->read(datastore.context, read_data, 0, sizeof(read_data), &bytes_read);
        TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);
        TEST_ASSERT_EQUAL_GOTO(bytes_read, sizeof(read_data), exit);

        TEST_ASSERT_MEMORY_EQUAL_GOTO(write_data, read_data, sizeof(write_data), exit);
    }

exit:
    status = cleanup_datastore(&datastore);
    TEST_ASSERT_EQUAL_CONTINUE(status, EL2GO_STATUS_SUCCESS);
    return test_status;
}

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
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    if (!check_datastore(datastore))
        goto exit;

    status = datastore.ops->init(datastore.context, NULL);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    fill_buffer(write_data, sizeof(write_data), 0);

    for (; i < 10; i++) {
        status = datastore.ops->allocate(datastore.context, 128);
        TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

        status = datastore.ops->write(datastore.context, write_data, 0, sizeof(write_data),
                                      &bytes_written);
        TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);
        TEST_ASSERT_EQUAL_GOTO(bytes_written, sizeof(write_data), exit);

        status = datastore.ops->commit(datastore.context);
        TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

        status =
            datastore.ops->read(datastore.context, read_data, 0, sizeof(read_data), &bytes_read);
        TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);
        TEST_ASSERT_EQUAL_GOTO(bytes_read, sizeof(read_data), exit);

        TEST_ASSERT_MEMORY_EQUAL_GOTO(write_data, read_data, sizeof(write_data), exit);
    }

exit:
    status = cleanup_datastore(&datastore);
    TEST_ASSERT_EQUAL_CONTINUE(status, EL2GO_STATUS_SUCCESS);

    return test_status;
}

/* ========================================================================== */
/* Test: Partial Read/Write Operations                                        */
/* ========================================================================== */

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
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    if (!check_datastore(datastore))
        goto exit;

    status = datastore.ops->init(datastore.context, NULL);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    /* Allocate 80 bytes */
    status = datastore.ops->allocate(datastore.context, 80);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    fill_buffer(write_data, sizeof(write_data), 0);

    /* Try to write 100 bytes - should only write 80 */
    status =
        datastore.ops->write(datastore.context, write_data, 0, sizeof(write_data), &bytes_written);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_INCOMPLETE_WRITE, exit);
    TEST_ASSERT_EQUAL_GOTO(bytes_written, 80, exit);

    status = datastore.ops->commit(datastore.context);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    /* Try to read 150 bytes - should only read 80 */
    status = datastore.ops->read(datastore.context, read_data, 0, sizeof(read_data), &bytes_read);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_INCOMPLETE_READ, exit);
    TEST_ASSERT_EQUAL_GOTO(bytes_read, 80, exit);

    /* Verify partial data is correct */
    TEST_ASSERT_MEMORY_EQUAL_CONTINUE(write_data, read_data, 80);

exit:
    status = cleanup_datastore(&datastore);
    TEST_ASSERT_EQUAL_CONTINUE(status, EL2GO_STATUS_SUCCESS);

    return test_status;
}

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
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    if (!check_datastore(datastore))
        goto exit;

    status = datastore.ops->init(datastore.context, NULL);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    /* Allocate space */
    status = datastore.ops->allocate(datastore.context, 256);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    fill_buffer(write_data, sizeof(write_data), 0);

    /* Write 100 bytes */
    status =
        datastore.ops->write(datastore.context, write_data, 0, sizeof(write_data), &bytes_written);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);
    TEST_ASSERT_EQUAL_GOTO(bytes_written, sizeof(write_data), exit);

    status = datastore.ops->commit(datastore.context);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    /* Try to read 150 bytes - should only read 100 (what was written) */
    status = datastore.ops->read(datastore.context, read_data, 0, sizeof(read_data), &bytes_read);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_INCOMPLETE_READ, exit);
    TEST_ASSERT_EQUAL_GOTO(bytes_read, 100, exit);

    /* Verify partial data is correct */
    TEST_ASSERT_MEMORY_EQUAL_CONTINUE(write_data, read_data, 100);

exit:
    status = cleanup_datastore(&datastore);
    TEST_ASSERT_EQUAL_CONTINUE(status, EL2GO_STATUS_SUCCESS);

    return test_status;
}

/* ========================================================================== */
/* Test: Bytes Read/Written NULL Pointer Tests                                */
/* ========================================================================== */

static bool test_datastore_plain_null_bytes_pointers(void *params)
{
    el2go_datastore_t datastore = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    uint8_t data[32] = { 0 };
    bool test_status = true;

    (void)params;

    status = el2go_datastore_plain_create(&datastore, NULL);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    if (!check_datastore(datastore))
        goto exit;

    status = datastore.ops->init(datastore.context, NULL);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    status = datastore.ops->allocate(datastore.context, 128);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    /* Test write with NULL bytes_written */
    status = datastore.ops->write(datastore.context, data, 0, sizeof(data), NULL);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_INVALID_PARAMETER, exit);

    status = datastore.ops->commit(datastore.context);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    /* Test read with NULL bytes_read */
    status = datastore.ops->read(datastore.context, data, 0, sizeof(data), NULL);
    TEST_ASSERT_EQUAL_CONTINUE(status, EL2GO_STATUS_INVALID_PARAMETER);

exit:
    status = cleanup_datastore(&datastore);
    TEST_ASSERT_EQUAL_CONTINUE(status, EL2GO_STATUS_SUCCESS);

    return test_status;
}

static bool test_datastore_fs_null_bytes_pointers(void *params)
{
    el2go_datastore_t datastore = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    uint8_t data[32] = { 0 };
    bool test_status = true;

    (void)params;

    status = el2go_datastore_fs_create(&datastore, __func__);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    if (!check_datastore(datastore))
        goto exit;

    status = datastore.ops->init(datastore.context, NULL);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    status = datastore.ops->allocate(datastore.context, 128);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    /* Test write with NULL bytes_written */
    status = datastore.ops->write(datastore.context, data, 0, sizeof(data), NULL);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_INVALID_PARAMETER, exit);

    status = datastore.ops->commit(datastore.context);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    /* Test read with NULL bytes_read */
    status = datastore.ops->read(datastore.context, data, 0, sizeof(data), NULL);
    TEST_ASSERT_EQUAL_CONTINUE(status, EL2GO_STATUS_INVALID_PARAMETER);

exit:
    status = cleanup_datastore(&datastore);
    TEST_ASSERT_EQUAL_CONTINUE(status, EL2GO_STATUS_SUCCESS);

    return test_status;
}

/* ========================================================================== */
/* Test: Edge Cases for Offset Operations                                     */
/* ========================================================================== */

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
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    if (!check_datastore(datastore))
        goto exit;

    status = datastore.ops->init(datastore.context, NULL);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    status = datastore.ops->allocate(datastore.context, 100);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    fill_buffer(write_data, sizeof(write_data), 0);

    /* Write at offset 68 (100 - 32 = 68, so this should fit exactly) */
    status =
        datastore.ops->write(datastore.context, write_data, 68, sizeof(write_data), &bytes_written);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);
    TEST_ASSERT_EQUAL_GOTO(bytes_written, sizeof(write_data), exit);

    status = datastore.ops->commit(datastore.context);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    /* Read from the same offset */
    status = datastore.ops->read(datastore.context, read_data, 68, sizeof(read_data), &bytes_read);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);
    TEST_ASSERT_EQUAL_GOTO(bytes_read, sizeof(read_data), exit);

    TEST_ASSERT_MEMORY_EQUAL_GOTO(write_data, read_data, sizeof(write_data), exit);

    /* Try to write at offset 69 (should partially fail) */
    bytes_written = 0;
    status = datastore.ops->allocate(datastore.context, 100);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    status =
        datastore.ops->write(datastore.context, write_data, 69, sizeof(write_data), &bytes_written);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_INCOMPLETE_WRITE, exit);
    TEST_ASSERT_EQUAL_CONTINUE(bytes_written, 31);

exit:
    status = cleanup_datastore(&datastore);
    TEST_ASSERT_EQUAL_CONTINUE(status, EL2GO_STATUS_SUCCESS);

    return test_status;
}

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
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    if (!check_datastore(datastore))
        goto exit;

    status = datastore.ops->init(datastore.context, NULL);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    status = datastore.ops->allocate(datastore.context, 256);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    fill_buffer(write_data, sizeof(write_data), 0);

    /* Write at offset 100 */
    status = datastore.ops->write(datastore.context, write_data, 100, sizeof(write_data),
                                  &bytes_written);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);
    TEST_ASSERT_EQUAL_GOTO(bytes_written, sizeof(write_data), exit);

    status = datastore.ops->commit(datastore.context);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    /* Read from the same offset */
    status = datastore.ops->read(datastore.context, read_data, 100, sizeof(read_data), &bytes_read);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);
    TEST_ASSERT_EQUAL_GOTO(bytes_read, sizeof(read_data), exit);

    TEST_ASSERT_MEMORY_EQUAL_CONTINUE(write_data, read_data, sizeof(write_data));

exit:
    status = cleanup_datastore(&datastore);
    TEST_ASSERT_EQUAL_CONTINUE(status, EL2GO_STATUS_SUCCESS);

    return test_status;
}

/* ========================================================================== */
/* Test: Zero Bytes Read/Written Scenarios                                    */
/* ========================================================================== */

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
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    if (!check_datastore(datastore))
        goto exit;

    status = datastore.ops->init(datastore.context, NULL);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    status = datastore.ops->allocate(datastore.context, 50);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    fill_buffer(write_data, sizeof(write_data), 0);

    status =
        datastore.ops->write(datastore.context, write_data, 0, sizeof(write_data), &bytes_written);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);
    TEST_ASSERT_EQUAL_GOTO(bytes_written, sizeof(write_data), exit);

    status = datastore.ops->commit(datastore.context);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    /* Try to read at offset 50 (exactly at the end) */
    status = datastore.ops->read(datastore.context, read_data, 50, sizeof(read_data), &bytes_read);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_BUFFER_TOO_SMALL, exit);
    TEST_ASSERT_EQUAL_CONTINUE(bytes_read, 0);

exit:
    status = cleanup_datastore(&datastore);
    TEST_ASSERT_EQUAL_CONTINUE(status, EL2GO_STATUS_SUCCESS);

    return test_status;
}

static bool test_datastore_plain_write_at_end(void *params)
{
    el2go_datastore_t datastore = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    uint8_t write_data[10] = { 0 };
    size_t bytes_written = 0;
    bool test_status = true;

    (void)params;

    status = el2go_datastore_plain_create(&datastore, NULL);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    if (!check_datastore(datastore))
        goto exit;

    status = datastore.ops->init(datastore.context, NULL);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    status = datastore.ops->allocate(datastore.context, 50);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_SUCCESS, exit);

    fill_buffer(write_data, sizeof(write_data), 0);

    /* Try to write at offset 50 (exactly at the end) */
    status =
        datastore.ops->write(datastore.context, write_data, 50, sizeof(write_data), &bytes_written);
    TEST_ASSERT_EQUAL_GOTO(status, EL2GO_STATUS_BUFFER_TOO_SMALL, exit);
    TEST_ASSERT_EQUAL_CONTINUE(bytes_written, 0);

exit:
    status = cleanup_datastore(&datastore);
    TEST_ASSERT_EQUAL_CONTINUE(status, EL2GO_STATUS_SUCCESS);

    return test_status;
}

/* ========================================================================== */
/* Test Registration                                                          */
/* ========================================================================== */

void register_datastore_tests(void)
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
}
