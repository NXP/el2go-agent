/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

/**
 * @file test_el2go_datastore_get_size.c
 * @brief Unit tests for el2go_datastore_get_size().
 *
 * get_size() returns the number of bytes actually written into the committed
 * slot (high-water mark), NOT the allocation size.
 *
 * Tests cover:
 *   - NULL argument guards (NULL datastore, NULL size pointer)
 *   - Size is 0 on a freshly initialised datastore (no committed data yet)
 *   - Size is 0 after allocate + commit with no write
 *   - Size equals bytes written after allocate + partial write + commit
 *   - Size equals full allocation when fully written and committed
 *   - Size updates correctly after re-allocation and re-commit
 *   - Size still reflects last committed value before the next commit
 */

#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "test_framework.h"

#include "osal.h"

#include "common/el2go_datastore.h"

/* ========================================================================== */
/* Local helpers                                                               */
/* ========================================================================== */

static bool setup_ds(el2go_datastore_t *ds, el2go_datastore_type_t type)
{
    return el2go_datastore_init(0, "test_gs", type, ds, NULL) == EL2GO_STATUS_SUCCESS;
}

static void cleanup_ds(el2go_datastore_t *ds)
{
    (void)el2go_datastore_free(ds);
}

/* ========================================================================== */
/* NULL guard tests                                                            */
/* ========================================================================== */

/**
 * @brief NULL datastore must return INVALID_PARAMETER.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_get_size_null_datastore(void *params)
{
    size_t sz = 0;
    el2go_status_t status = EL2GO_STATUS_SUCCESS;

    (void)params;

    status = el2go_datastore_get_size(NULL, &sz);
    TEST_ASSERT_EQUAL(EL2GO_STATUS_INVALID_PARAMETER, status);
    return true;
}

/**
 * @brief NULL size pointer must return INVALID_PARAMETER.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_get_size_null_size_ptr(void *params)
{
    el2go_datastore_t ds = { 0 };
    el2go_datastore_type_t type = *(const el2go_datastore_type_t *)params;
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    bool test_status = true;

    TEST_ASSERT_GOTO(setup_ds(&ds, type), exit);
    status = el2go_datastore_get_size(&ds, NULL);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_INVALID_PARAMETER, status, exit);

exit:
    cleanup_ds(&ds);
    return test_status;
}

/* ========================================================================== */
/* Functional tests                                                            */
/* ========================================================================== */

/**
 * @brief Freshly initialised datastore - no committed data, size is 0.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_get_size_fresh_datastore(void *params)
{
    el2go_datastore_t ds = { 0 };
    el2go_datastore_type_t type = *(const el2go_datastore_type_t *)params;
    size_t sz = 42; /* init to non-zero to verify it is overwritten */
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    bool test_status = true;

    TEST_ASSERT_GOTO(setup_ds(&ds, type), exit);

    status = el2go_datastore_get_size(&ds, &sz);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    TEST_ASSERT_EQUAL_GOTO(0U, sz, exit);

exit:
    cleanup_ds(&ds);
    return test_status;
}

/**
 * @brief After allocate + commit with no write, size is 0 (nothing written).
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_get_size_after_allocate_commit_no_write(void *params)
{
    el2go_datastore_t ds = { 0 };
    el2go_datastore_type_t type = *(const el2go_datastore_type_t *)params;
    size_t sz = 42;
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    bool test_status = true;

    TEST_ASSERT_GOTO(setup_ds(&ds, type), exit);

    status = el2go_datastore_allocate(&ds, 64);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    status = el2go_datastore_commit(&ds);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    status = el2go_datastore_get_size(&ds, &sz);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    TEST_ASSERT_EQUAL_GOTO(0U, sz, exit);

exit:
    cleanup_ds(&ds);
    return test_status;
}

/**
 * @brief Verify that after a partial write and commit, get_size() returns
 *        the number of bytes actually written, not the allocation length.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_get_size_partial_write(void *params)
{
    el2go_datastore_t ds = { 0 };
    el2go_datastore_type_t type = *(const el2go_datastore_type_t *)params;
    const size_t alloc_len = 64;
    const uint8_t data[16] = { 0xAA };
    size_t bytes_written = 0;
    size_t sz = 0;
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    bool test_status = true;

    TEST_ASSERT_GOTO(setup_ds(&ds, type), exit);

    status = el2go_datastore_allocate(&ds, alloc_len);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    status = el2go_datastore_write(&ds, data, 0, sizeof(data), &bytes_written);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    TEST_ASSERT_EQUAL_GOTO(sizeof(data), bytes_written, exit);
    status = el2go_datastore_commit(&ds);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    status = el2go_datastore_get_size(&ds, &sz);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    /* size must be bytes written (16), not allocation size (64). */
    TEST_ASSERT_EQUAL_GOTO(sizeof(data), sz, exit);

exit:
    cleanup_ds(&ds);
    return test_status;
}

/**
 * @brief After a full write + commit, size equals the full written length.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_get_size_full_write(void *params)
{
    el2go_datastore_t ds = { 0 };
    el2go_datastore_type_t type = *(const el2go_datastore_type_t *)params;
    const size_t data_len = 32;
    uint8_t data[32];
    size_t bytes_written = 0;
    size_t sz = 0;
    size_t i = 0;
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    bool test_status = true;

    for (i = 0; i < data_len; i++)
        data[i] = (uint8_t)i;

    TEST_ASSERT_GOTO(setup_ds(&ds, type), exit);

    status = el2go_datastore_allocate(&ds, data_len);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    status = el2go_datastore_write(&ds, data, 0, data_len, &bytes_written);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    TEST_ASSERT_EQUAL_GOTO(data_len, bytes_written, exit);
    status = el2go_datastore_commit(&ds);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    status = el2go_datastore_get_size(&ds, &sz);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    TEST_ASSERT_EQUAL_GOTO(data_len, sz, exit);

exit:
    cleanup_ds(&ds);
    return test_status;
}

/**
 * @brief Re-allocating + re-writing updates size to the new written length.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_get_size_after_realloc(void *params)
{
    el2go_datastore_t ds = { 0 };
    el2go_datastore_type_t type = *(const el2go_datastore_type_t *)params;
    const uint8_t data_small[8] = { 0x11 };
    const uint8_t data_large[32] = { 0x22 };
    size_t bytes_written = 0;
    size_t sz = 0;
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    bool test_status = true;

    TEST_ASSERT_GOTO(setup_ds(&ds, type), exit);

    /* First transaction: allocate 64, write 8. */
    status = el2go_datastore_allocate(&ds, 64);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    status = el2go_datastore_write(&ds, data_small, 0, sizeof(data_small), &bytes_written);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    status = el2go_datastore_commit(&ds);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    status = el2go_datastore_get_size(&ds, &sz);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    TEST_ASSERT_EQUAL_GOTO(sizeof(data_small), sz, exit);

    /* Second transaction: allocate 64, write 32. */
    status = el2go_datastore_allocate(&ds, 64);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    status = el2go_datastore_write(&ds, data_large, 0, sizeof(data_large), &bytes_written);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    status = el2go_datastore_commit(&ds);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    status = el2go_datastore_get_size(&ds, &sz);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    TEST_ASSERT_EQUAL_GOTO(sizeof(data_large), sz, exit);

exit:
    cleanup_ds(&ds);
    return test_status;
}

/**
 * @brief get_size before commit returns the last committed size, not the
 *        size of a pending (not yet committed) write.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_get_size_before_commit(void *params)
{
    el2go_datastore_t ds = { 0 };
    el2go_datastore_type_t type = *(const el2go_datastore_type_t *)params;
    const uint8_t data_first[8] = { 0xAA };
    const uint8_t data_second[32] = { 0xBB };
    size_t bytes_written = 0;
    size_t sz = 0;
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    bool test_status = true;

    TEST_ASSERT_GOTO(setup_ds(&ds, type), exit);

    /* Commit first write so there is a valid read slot. */
    status = el2go_datastore_allocate(&ds, 64);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    status = el2go_datastore_write(&ds, data_first, 0, sizeof(data_first), &bytes_written);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    status = el2go_datastore_commit(&ds);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    /* Start a second transaction but do NOT commit it. */
    status = el2go_datastore_allocate(&ds, 64);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    status = el2go_datastore_write(&ds, data_second, 0, sizeof(data_second), &bytes_written);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    /* get_size should still reflect the first committed write. */
    status = el2go_datastore_get_size(&ds, &sz);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    TEST_ASSERT_EQUAL_GOTO(sizeof(data_first), sz, exit);

exit:
    cleanup_ds(&ds);
    return test_status;
}

/* ========================================================================== */
/* Test registration                                                           */
/* ========================================================================== */

void register_datastore_get_size_tests(bool include_fs_tests)
{
    static el2go_datastore_type_t s_plain = EL2GO_DATASTORE_TYPE_PLAIN;
    static el2go_datastore_type_t s_fs = EL2GO_DATASTORE_TYPE_FS;

    /* NULL datastore test is type-independent. */
    TEST_REGISTER(test_get_size_null_datastore);

    /* PLAIN variants - always registered. */
    TEST_REGISTER_WITH_PARAMS(test_get_size_null_size_ptr, &s_plain);
    TEST_REGISTER_WITH_PARAMS(test_get_size_fresh_datastore, &s_plain);
    TEST_REGISTER_WITH_PARAMS(test_get_size_after_allocate_commit_no_write, &s_plain);
    TEST_REGISTER_WITH_PARAMS(test_get_size_partial_write, &s_plain);
    TEST_REGISTER_WITH_PARAMS(test_get_size_full_write, &s_plain);
    TEST_REGISTER_WITH_PARAMS(test_get_size_after_realloc, &s_plain);
    TEST_REGISTER_WITH_PARAMS(test_get_size_before_commit, &s_plain);

    /* FS variants - only when filesystem support is available. */
    if (include_fs_tests) {
        TEST_REGISTER_WITH_PARAMS(test_get_size_null_size_ptr, &s_fs);
        TEST_REGISTER_WITH_PARAMS(test_get_size_fresh_datastore, &s_fs);
        TEST_REGISTER_WITH_PARAMS(test_get_size_after_allocate_commit_no_write, &s_fs);
        TEST_REGISTER_WITH_PARAMS(test_get_size_partial_write, &s_fs);
        TEST_REGISTER_WITH_PARAMS(test_get_size_full_write, &s_fs);
        TEST_REGISTER_WITH_PARAMS(test_get_size_after_realloc, &s_fs);
        TEST_REGISTER_WITH_PARAMS(test_get_size_before_commit, &s_fs);
    }
}
