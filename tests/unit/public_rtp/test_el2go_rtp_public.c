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

/* ========================================================================== */
/* RTP Context Initialization and Cleanup Tests                               */
/* ========================================================================== */

static bool test_el2go_rtp_init_and_free(void *params)
{
    el2go_rtp_ctx_t *ctx = NULL;
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    bool test_status = true;

    (void)params;

    status = el2go_rtp_init(&ctx);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    TEST_ASSERT_NOT_NULL_GOTO(ctx, exit);

    status = el2go_rtp_free(&ctx);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    TEST_ASSERT_NULL_CONTINUE(ctx);

exit:
    return test_status;
}

static bool test_el2go_rtp_null_parameters(void *params)
{
    el2go_status_t status = EL2GO_STATUS_SUCCESS;

    (void)params;

    status = el2go_rtp_init(NULL);
    TEST_ASSERT_EQUAL(EL2GO_STATUS_INVALID_PARAMETER, status);

    status = el2go_rtp_free(NULL);
    TEST_ASSERT_EQUAL(EL2GO_STATUS_INVALID_PARAMETER, status);

    return true;
}

/* ========================================================================== */
/* Datastore Registration - NULL Parameter Tests                              */
/* ========================================================================== */

static bool test_el2go_rtp_datastore_add_remove_null_parameters(void *params)
{
    el2go_rtp_ctx_t *ctx = NULL;
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    bool test_status = true;

    (void)params;

    status = el2go_rtp_init(&ctx);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    status = el2go_rtp_datastore_add(ctx, NULL);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_INVALID_PARAMETER, status, cleanup);

    status = el2go_rtp_datastore_add(NULL, NULL);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_INVALID_PARAMETER, status, cleanup);

    status = el2go_rtp_datastore_remove(ctx, NULL);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_INVALID_PARAMETER, status, cleanup);

    status = el2go_rtp_datastore_remove(NULL, NULL);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_INVALID_PARAMETER, status);

cleanup:
    status = el2go_rtp_free(&ctx);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_SUCCESS, status);

exit:
    return test_status;
}

/* ========================================================================== */
/* Datastore Registration - Basic Operations Tests                            */
/* ========================================================================== */

static bool test_el2go_rtp_datastore_add_remove(void *params)
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

    /* Add all datastores */
    for (i = 0; i < EL2GO_RTP_MAX_DATASTORES; i++) {
        status = el2go_rtp_datastore_add(ctx, &datastores[i]);
        TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup);
    }

    /* Remove all datastores */
    for (i = 0; i < EL2GO_RTP_MAX_DATASTORES; i++) {
        status = el2go_rtp_datastore_remove(ctx, &datastores[i]);
        TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup);
    }

    /* Now we should be able to add the extra one */
    status = el2go_rtp_datastore_add(ctx, &datastores[EL2GO_RTP_MAX_DATASTORES]);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_SUCCESS, status);

cleanup:
    status = el2go_rtp_free(&ctx);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_SUCCESS, status);

exit:
    return test_status;
}

/* ========================================================================== */
/* Datastore Registration - Error Conditions Tests                            */
/* ========================================================================== */

static bool test_el2go_rtp_datastore_remove_not_found(void *params)
{
    el2go_rtp_ctx_t *ctx = NULL;
    el2go_datastore_t datastores[EL2GO_RTP_MAX_DATASTORES + 1] = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    bool test_status = true;
    size_t i = 0;

    (void)params;

    init_datastores(datastores, EL2GO_RTP_MAX_DATASTORES + 1, 0x70000000);

    status = el2go_rtp_init(&ctx);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    for (i = 0; i < EL2GO_RTP_MAX_DATASTORES; i++) {
        status = el2go_rtp_datastore_add(ctx, &datastores[i]);
        TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup);
    }

    /* Try to remove a datastore that was never added */
    status = el2go_rtp_datastore_remove(ctx, &datastores[EL2GO_RTP_MAX_DATASTORES]);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_NOT_FOUND, status, cleanup);

    /* Remove all datastores */
    for (i = 0; i < EL2GO_RTP_MAX_DATASTORES; i++) {
        status = el2go_rtp_datastore_remove(ctx, &datastores[i]);
        TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup);
    }

    /* Try to remove datastores that were already removed */
    for (i = 0; i < EL2GO_RTP_MAX_DATASTORES; i++) {
        status = el2go_rtp_datastore_remove(ctx, &datastores[i]);
        TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_INVALID_STATE, status, cleanup);
    }

cleanup:
    status = el2go_rtp_free(&ctx);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_SUCCESS, status);

exit:
    return test_status;
}

/* ========================================================================== */
/* Datastore Registration - Resource Limits Tests                             */
/* ========================================================================== */

static bool test_el2go_rtp_datastore_add_max_limit(void *params)
{
    el2go_rtp_ctx_t *ctx = NULL;
    el2go_datastore_t datastores[EL2GO_RTP_MAX_DATASTORES + 1] = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    bool test_status = true;
    size_t i = 0;

    (void)params;

    init_datastores(datastores, EL2GO_RTP_MAX_DATASTORES + 1, 0x70000000);

    status = el2go_rtp_init(&ctx);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    /* Add maximum allowed datastores */
    for (i = 0; i < EL2GO_RTP_MAX_DATASTORES; i++) {
        status = el2go_rtp_datastore_add(ctx, &datastores[i]);
        TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup);
    }

    /* Try to add one more */
    status = el2go_rtp_datastore_add(ctx, &datastores[EL2GO_RTP_MAX_DATASTORES]);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_RESOURCE_LIMIT, status);

cleanup:
    status = el2go_rtp_free(&ctx);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_SUCCESS, status);

exit:
    return test_status;
}

/* ========================================================================== */
/* Datastore Get By ID - NULL Parameter Tests                                 */
/* ========================================================================== */

static bool test_el2go_get_datastore_by_id_null_parameters(void *params)
{
    el2go_rtp_ctx_t *ctx = NULL;
    el2go_datastore_t *datastore = NULL;
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    bool test_status = true;

    (void)params;

    status = el2go_rtp_init(&ctx);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    /* Test NULL context */
    status = el2go_rtp_get_datastore_by_id(NULL, 0x70000000, &datastore);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_INVALID_PARAMETER, status, cleanup);

    /* Test NULL datastore pointer */
    status = el2go_rtp_get_datastore_by_id(ctx, 0x70000000, NULL);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_INVALID_PARAMETER, status, cleanup);

    /* Test both NULL */
    status = el2go_rtp_get_datastore_by_id(NULL, 0x70000000, NULL);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_INVALID_PARAMETER, status);

cleanup:
    status = el2go_rtp_free(&ctx);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_SUCCESS, status);

exit:
    return test_status;
}

/* ========================================================================== */
/* Datastore Get By ID - Basic Operations Tests                               */
/* ========================================================================== */

static bool test_el2go_get_datastore_by_id_success(void *params)
{
    el2go_rtp_ctx_t *ctx = NULL;
    el2go_datastore_t datastores[EL2GO_RTP_MAX_DATASTORES] = { 0 };
    el2go_datastore_t *retrieved_datastore = NULL;
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    bool test_status = true;
    size_t i = 0;

    (void)params;

    init_datastores(datastores, EL2GO_RTP_MAX_DATASTORES, 0x70000000);

    status = el2go_rtp_init(&ctx);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    /* Add all datastores */
    for (i = 0; i < EL2GO_RTP_MAX_DATASTORES; i++) {
        status = el2go_rtp_datastore_add(ctx, &datastores[i]);
        TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup);
    }

    /* Retrieve each datastore by ID and verify */
    for (i = 0; i < EL2GO_RTP_MAX_DATASTORES; i++) {
        status = el2go_rtp_get_datastore_by_id(ctx, datastores[i].id, &retrieved_datastore);
        TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup);
        TEST_ASSERT_NOT_NULL_GOTO(retrieved_datastore, cleanup);
        TEST_ASSERT_EQUAL_GOTO(datastores[i].id, retrieved_datastore->id, cleanup);
        TEST_ASSERT_PTR_EQUAL_GOTO(&datastores[i], retrieved_datastore, cleanup);
    }

cleanup:
    status = el2go_rtp_free(&ctx);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_SUCCESS, status);

exit:
    return test_status;
}

/* ========================================================================== */
/* Datastore Get By ID - Error Conditions Tests                               */
/* ========================================================================== */

static bool test_el2go_get_datastore_by_id_not_found(void *params)
{
    el2go_rtp_ctx_t *ctx = NULL;
    el2go_datastore_t datastores[EL2GO_RTP_MAX_DATASTORES] = { 0 };
    el2go_datastore_t *retrieved_datastore = NULL;
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    bool test_status = true;
    size_t i = 0;

    (void)params;

    init_datastores(datastores, EL2GO_RTP_MAX_DATASTORES, 0x70000000);

    status = el2go_rtp_init(&ctx);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    /* Try to get datastore from empty context */
    status = el2go_rtp_get_datastore_by_id(ctx, 0x70000000, &retrieved_datastore);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_NOT_FOUND, status, cleanup);

    /* Add all datastores */
    for (i = 0; i < EL2GO_RTP_MAX_DATASTORES; i++) {
        status = el2go_rtp_datastore_add(ctx, &datastores[i]);
        TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup);
    }

    /* Try to get datastore with non-existent ID */
    status = el2go_rtp_get_datastore_by_id(ctx, 0x99999999, &retrieved_datastore);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_NOT_FOUND, status);

cleanup:
    status = el2go_rtp_free(&ctx);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_SUCCESS, status);

exit:
    return test_status;
}

/* ========================================================================== */
/* Test Registration                                                          */
/* ========================================================================== */

void register_el2go_rtp_tests(void)
{
    TEST_REGISTER(test_el2go_rtp_init_and_free);
    TEST_REGISTER(test_el2go_rtp_null_parameters);
    TEST_REGISTER(test_el2go_rtp_datastore_add_remove_null_parameters);
    TEST_REGISTER(test_el2go_rtp_datastore_add_remove);
    TEST_REGISTER(test_el2go_rtp_datastore_remove_not_found);
    TEST_REGISTER(test_el2go_rtp_datastore_add_max_limit);
    TEST_REGISTER(test_el2go_get_datastore_by_id_null_parameters);
    TEST_REGISTER(test_el2go_get_datastore_by_id_success);
    TEST_REGISTER(test_el2go_get_datastore_by_id_not_found);
}
