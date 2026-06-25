/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "rtp/el2go_rtp.h"
#include "rtp/el2go_rtp_config.h"
#include "test_framework.h"
#include "test_suites.h"
#include "test_utils.h"
#include "el2go_rtp_internal.h"

/** @defgroup test_el2go_rtp_internal Internal RTP Tests
 * @brief Unit tests for the internal RTP module.
 *
 * Covers RTP context structure validation, datastore and keystore counter
 * tracking, and internal storage verification during add/remove operations.
 * @{
 */

/**
 * @brief Test RTP context structure initialization.
 *
 * Verifies that a newly initialized RTP context has zero keystores and
 * datastores, and that the context can be properly freed and set to @c NULL.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_el2go_rtp_context_structure(void *params)
{
    el2go_rtp_ctx_t *ctx = NULL;
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    bool test_status = true;

    (void)params;

    status = el2go_rtp_init(&ctx);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    TEST_ASSERT_NOT_NULL_GOTO(ctx, exit);

    TEST_ASSERT_EQUAL_GOTO(0, ctx->num_keystores, cleanup);
    TEST_ASSERT_EQUAL_CONTINUE(0, ctx->num_datastores);

cleanup:
    status = el2go_rtp_free(&ctx);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    TEST_ASSERT_NULL(ctx);

exit:
    return test_status;
}

/**
 * @brief Test datastore counter tracking during add and remove operations.
 *
 * Verifies that the internal datastore counter is correctly incremented when
 * datastores are added up to the maximum limit, and correctly decremented
 * when they are removed one by one until reaching zero.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_el2go_rtp_datastore_count(void *params)
{
    el2go_rtp_ctx_t *ctx = NULL;
    el2go_datastore_t datastores[EL2GO_RTP_MAX_DATASTORES] = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    bool test_status = true;
    size_t i = 0;

    (void)params;

    init_datastores(datastores, EL2GO_RTP_MAX_DATASTORES, 0x70000000);

    status = el2go_rtp_init(&ctx);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    TEST_ASSERT_NOT_NULL_GOTO(ctx, exit);

    TEST_ASSERT_EQUAL_GOTO(0, ctx->num_datastores, cleanup);

    /* Add datastores up to the limit */
    for (i = 0; i < EL2GO_RTP_MAX_DATASTORES; i++) {
        status = el2go_rtp_add_datastore(ctx, &datastores[i]);
        TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup);
        TEST_ASSERT_EQUAL_GOTO(i + 1, ctx->num_datastores, cleanup);
    }

    /* Remove datastores one by one */
    for (i = 0; i < EL2GO_RTP_MAX_DATASTORES; i++) {
        status = el2go_rtp_remove_datastore(ctx, &datastores[i]);
        TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup);
        TEST_ASSERT_EQUAL_GOTO(EL2GO_RTP_MAX_DATASTORES - i - 1, ctx->num_datastores, cleanup);
    }

    TEST_ASSERT_EQUAL_CONTINUE(0, ctx->num_datastores);

cleanup:
    status = el2go_rtp_free(&ctx);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    TEST_ASSERT_NULL(ctx);

exit:
    return test_status;
}

/**
 * @brief Test datastore internal storage during add operations.
 *
 * Verifies that datastores are correctly stored in the internal array and
 * that their IDs match the expected values after each add operation.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_el2go_rtp_datastore_internal_storage(void *params)
{
    el2go_rtp_ctx_t *ctx = NULL;
    el2go_datastore_t datastores[EL2GO_RTP_MAX_DATASTORES] = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    bool test_status = true;
    size_t i = 0;

    (void)params;

    init_datastores(datastores, EL2GO_RTP_MAX_DATASTORES, 0x70000000);

    status = el2go_rtp_init(&ctx);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    TEST_ASSERT_NOT_NULL_GOTO(ctx, exit);

    /* Add datastores and verify storage */
    for (i = 0; i < EL2GO_RTP_MAX_DATASTORES; i++) {
        status = el2go_rtp_add_datastore(ctx, &datastores[i]);
        TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup);
        TEST_ASSERT_EQUAL_GOTO(i + 1, ctx->num_datastores, cleanup);
        TEST_ASSERT_EQUAL_GOTO(datastores[i].id, ctx->datastores[i]->id, cleanup);
    }

cleanup:
    status = el2go_rtp_free(&ctx);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    TEST_ASSERT_NULL(ctx);

exit:
    return test_status;
}

/**
 * @brief Test keystore counter tracking during add and remove operations.
 *
 * Verifies that the internal keystore counter is correctly incremented when
 * keystores are added up to the maximum limit, and correctly decremented
 * when they are removed one by one until reaching zero.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_el2go_rtp_keystore_count(void *params)
{
    el2go_rtp_ctx_t *ctx = NULL;
    el2go_keystore_t keystores[EL2GO_RTP_MAX_KEYSTORES] = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    bool test_status = true;
    size_t i = 0;

    (void)params;

    init_keystores(keystores, EL2GO_RTP_MAX_KEYSTORES, 0x80000000);

    status = el2go_rtp_init(&ctx);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    TEST_ASSERT_NOT_NULL_GOTO(ctx, exit);

    TEST_ASSERT_EQUAL_GOTO(0, ctx->num_keystores, cleanup);

    /* Add keystores up to the limit */
    for (i = 0; i < EL2GO_RTP_MAX_KEYSTORES; i++) {
        status = el2go_rtp_add_keystore(ctx, &keystores[i]);
        TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup);
        TEST_ASSERT_EQUAL_GOTO(i + 1, ctx->num_keystores, cleanup);
    }

    /* Remove keystores one by one */
    for (i = 0; i < EL2GO_RTP_MAX_KEYSTORES; i++) {
        status = el2go_rtp_remove_keystore(ctx, &keystores[i]);
        TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup);
        TEST_ASSERT_EQUAL_GOTO(EL2GO_RTP_MAX_KEYSTORES - i - 1, ctx->num_keystores, cleanup);
    }

    TEST_ASSERT_EQUAL_CONTINUE(0, ctx->num_keystores);

cleanup:
    status = el2go_rtp_free(&ctx);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    TEST_ASSERT_NULL(ctx);

exit:
    return test_status;
}

/**
 * @brief Test keystore internal storage during add operations.
 *
 * Verifies that keystores are correctly stored in the internal array and
 * that their IDs match the expected values after each add operation.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_el2go_rtp_keystore_internal_storage(void *params)
{
    el2go_rtp_ctx_t *ctx = NULL;
    el2go_keystore_t keystores[EL2GO_RTP_MAX_KEYSTORES] = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    bool test_status = true;
    size_t i = 0;

    (void)params;

    init_keystores(keystores, EL2GO_RTP_MAX_KEYSTORES, 0x80000000);

    status = el2go_rtp_init(&ctx);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    TEST_ASSERT_NOT_NULL_GOTO(ctx, exit);

    /* Add keystores and verify storage */
    for (i = 0; i < EL2GO_RTP_MAX_KEYSTORES; i++) {
        status = el2go_rtp_add_keystore(ctx, &keystores[i]);
        TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup);
        TEST_ASSERT_EQUAL_GOTO(i + 1, ctx->num_keystores, cleanup);
        TEST_ASSERT_EQUAL_GOTO(keystores[i].id, ctx->keystores[i]->id, cleanup);
    }

cleanup:
    status = el2go_rtp_free(&ctx);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    TEST_ASSERT_NULL(ctx);

exit:
    return test_status;
}

/**
 * @brief Register all internal RTP tests with the test framework.
 *
 * Registers every test function in the order they should be executed.
 */
void register_el2go_rtp_tests(void)
{
    TEST_REGISTER(test_el2go_rtp_context_structure);
    TEST_REGISTER(test_el2go_rtp_datastore_count);
    TEST_REGISTER(test_el2go_rtp_datastore_internal_storage);
    TEST_REGISTER(test_el2go_rtp_keystore_count);
    TEST_REGISTER(test_el2go_rtp_keystore_internal_storage);
}

/** @} */ /* end of test_el2go_rtp_internal */
