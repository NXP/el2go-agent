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

/* ========================================================================== */
/* Simple Internal Test - Verify Agent Context Structure                      */
/* ========================================================================== */

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

/* ========================================================================== */
/* Datastore Counter Validation Tests                                         */
/* ========================================================================== */

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
        status = el2go_rtp_datastore_add(ctx, &datastores[i]);
        TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup);
        TEST_ASSERT_EQUAL_GOTO(i + 1, ctx->num_datastores, cleanup);
    }

    /* Remove datastores one by one */
    for (i = 0; i < EL2GO_RTP_MAX_DATASTORES; i++) {
        status = el2go_rtp_datastore_remove(ctx, &datastores[i]);
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

/* ========================================================================== */
/* Storage Validation Tests                                                   */
/* ========================================================================== */

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
        status = el2go_rtp_datastore_add(ctx, &datastores[i]);
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

/* ========================================================================== */
/* Test Registration                                                          */
/* ========================================================================== */

void register_el2go_rtp_tests(void)
{
    TEST_REGISTER(test_el2go_rtp_context_structure);
    TEST_REGISTER(test_el2go_rtp_datastore_count);
    TEST_REGISTER(test_el2go_rtp_datastore_internal_storage);
}
