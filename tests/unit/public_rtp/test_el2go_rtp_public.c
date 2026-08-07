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

#include "test_el2go_rtp_provision.h"

/** @defgroup test_el2go_rtp_public Public RTP API Tests
 * @brief Unit tests for the public RTP API.
 *
 * Covers RTP context initialization and cleanup, datastore and keystore
 * registration (add/remove), parameter validation, resource limits, retrieval
 * by ID, error conditions, and ID uniqueness enforcement across datastores
 * and keystores.
 * @{
 */

/**
 * @brief Test RTP context initialization and cleanup.
 *
 * Verifies that an RTP context can be successfully initialized and that it
 * is properly freed and set to @c NULL when cleaned up.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
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

/**
 * @brief Test RTP initialization and free with NULL parameters.
 *
 * Verifies that passing @c NULL to init and free functions returns an
 * invalid parameter error.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
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

/**
 * @brief Test datastore add and remove with NULL parameters.
 *
 * Verifies that passing @c NULL for the datastore pointer or context returns
 * an invalid parameter error for both add and remove operations.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_el2go_rtp_datastore_add_remove_null_parameters(void *params)
{
    el2go_rtp_ctx_t *ctx = NULL;
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    bool test_status = true;

    (void)params;

    status = el2go_rtp_init(&ctx);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    status = el2go_rtp_add_datastore(ctx, NULL);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_INVALID_PARAMETER, status, cleanup);

    status = el2go_rtp_add_datastore(NULL, NULL);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_INVALID_PARAMETER, status, cleanup);

    status = el2go_rtp_remove_datastore(ctx, NULL);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_INVALID_PARAMETER, status, cleanup);

    status = el2go_rtp_remove_datastore(NULL, NULL);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_INVALID_PARAMETER, status);

cleanup:
    status = el2go_rtp_free(&ctx);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_SUCCESS, status);

exit:
    return test_status;
}

/**
 * @brief Test datastore add and remove basic operations.
 *
 * Verifies that datastores can be added up to the maximum limit, removed
 * successfully, and that after removal a new datastore can be added.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
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
        status = el2go_rtp_add_datastore(ctx, &datastores[i]);
        TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup);
    }

    /* Remove all datastores */
    for (i = 0; i < EL2GO_RTP_MAX_DATASTORES; i++) {
        status = el2go_rtp_remove_datastore(ctx, &datastores[i]);
        TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup);
    }

    status = el2go_rtp_add_datastore(ctx, &datastores[EL2GO_RTP_MAX_DATASTORES]);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_SUCCESS, status);

cleanup:
    status = el2go_rtp_free(&ctx);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_SUCCESS, status);

exit:
    return test_status;
}

/**
 * @brief Test datastore removal when not found.
 *
 * Verifies that attempting to remove a datastore that was never added returns
 * a not found error, and that removing already-removed datastores returns an
 * invalid state error.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_el2go_rtp_datastore_remove_not_found(void *params)
{
    el2go_rtp_ctx_t *ctx = NULL;
    el2go_datastore_t datastores[EL2GO_RTP_MAX_DATASTORES + 1] = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    bool test_status = true;
    size_t i = 0;

    (void)params;

    init_datastores(datastores, EL2GO_RTP_MAX_DATASTORES + 1, 0x70000001);

    status = el2go_rtp_init(&ctx);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    for (i = 0; i < EL2GO_RTP_MAX_DATASTORES; i++) {
        status = el2go_rtp_add_datastore(ctx, &datastores[i]);
        TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup);
    }

    status = el2go_rtp_remove_datastore(ctx, &datastores[EL2GO_RTP_MAX_DATASTORES]);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_NOT_FOUND, status, cleanup);

    /* Remove all datastores */
    for (i = 0; i < EL2GO_RTP_MAX_DATASTORES; i++) {
        status = el2go_rtp_remove_datastore(ctx, &datastores[i]);
        TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup);
    }

    /* Try to remove datastores that were already removed */
    for (i = 0; i < EL2GO_RTP_MAX_DATASTORES; i++) {
        status = el2go_rtp_remove_datastore(ctx, &datastores[i]);
        TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_INVALID_STATE, status, cleanup);
    }

cleanup:
    status = el2go_rtp_free(&ctx);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_SUCCESS, status);

exit:
    return test_status;
}

/**
 * @brief Test datastore addition at maximum limit.
 *
 * Verifies that datastores can be added up to the maximum limit and that
 * attempting to add one more returns a resource limit error.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_el2go_rtp_datastore_add_max_limit(void *params)
{
    el2go_rtp_ctx_t *ctx = NULL;
    el2go_datastore_t datastores[EL2GO_RTP_MAX_DATASTORES + 1] = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    bool test_status = true;
    size_t i = 0;

    (void)params;

    init_datastores(datastores, EL2GO_RTP_MAX_DATASTORES + 1, 0x70000001);

    status = el2go_rtp_init(&ctx);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    /* Add maximum allowed datastores */
    for (i = 0; i < EL2GO_RTP_MAX_DATASTORES; i++) {
        status = el2go_rtp_add_datastore(ctx, &datastores[i]);
        TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup);
    }

    status = el2go_rtp_add_datastore(ctx, &datastores[EL2GO_RTP_MAX_DATASTORES]);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_RESOURCE_LIMIT, status);

cleanup:
    status = el2go_rtp_free(&ctx);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_SUCCESS, status);

exit:
    return test_status;
}

/**
 * @brief Test datastore retrieval by ID with NULL parameters.
 *
 * Verifies that passing @c NULL for the context or output pointer returns
 * an invalid parameter error.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
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

/**
 * @brief Test successful datastore retrieval by ID.
 *
 * Verifies that all added datastores can be successfully retrieved by their
 * IDs and that the retrieved pointers match the original datastore addresses.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
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
        status = el2go_rtp_add_datastore(ctx, &datastores[i]);
        TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup);
    }

    /* Retrieve each datastore by ID and verify */
    for (i = 0; i < EL2GO_RTP_MAX_DATASTORES; i++) {
        status = el2go_rtp_get_datastore_by_id(ctx, datastores[i].id, &retrieved_datastore);
        TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup);
        TEST_ASSERT_NOT_NULL_GOTO(retrieved_datastore, cleanup);
        TEST_ASSERT_GOTO(datastores[i].id == retrieved_datastore->id, cleanup);
        TEST_ASSERT_PTR_EQUAL_GOTO(&datastores[i], retrieved_datastore, cleanup);
    }

cleanup:
    status = el2go_rtp_free(&ctx);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_SUCCESS, status);

exit:
    return test_status;
}

/**
 * @brief Test datastore retrieval by ID when not found.
 *
 * Verifies that attempting to retrieve a datastore from an empty context or
 * with a non-existent ID returns a not found error.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
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
        status = el2go_rtp_add_datastore(ctx, &datastores[i]);
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

/**
 * @brief Test keystore add and remove with NULL parameters.
 *
 * Verifies that passing @c NULL for the keystore pointer or context returns
 * an invalid parameter error for both add and remove operations.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_el2go_rtp_keystore_add_remove_null_parameters(void *params)
{
    el2go_rtp_ctx_t *ctx = NULL;
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    bool test_status = true;

    (void)params;

    status = el2go_rtp_init(&ctx);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    status = el2go_rtp_add_keystore(ctx, NULL);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_INVALID_PARAMETER, status, cleanup);

    status = el2go_rtp_add_keystore(NULL, NULL);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_INVALID_PARAMETER, status, cleanup);

    status = el2go_rtp_remove_keystore(ctx, NULL);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_INVALID_PARAMETER, status, cleanup);

    status = el2go_rtp_remove_keystore(NULL, NULL);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_INVALID_PARAMETER, status);

cleanup:
    status = el2go_rtp_free(&ctx);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_SUCCESS, status);

exit:
    return test_status;
}

/**
 * @brief Test keystore add and remove basic operations.
 *
 * Verifies that keystores can be added up to the maximum limit, removed
 * successfully, and that after removal a new keystore can be added.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_el2go_rtp_keystore_add_remove(void *params)
{
    el2go_rtp_ctx_t *ctx = NULL;
    el2go_keystore_t keystores[EL2GO_RTP_MAX_KEYSTORES + 1] = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    bool test_status = true;
    size_t i = 0;

    (void)params;

    init_keystores(keystores, EL2GO_RTP_MAX_KEYSTORES + 1, 0x80000000);

    status = el2go_rtp_init(&ctx);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    /* Add all keystores */
    for (i = 0; i < EL2GO_RTP_MAX_KEYSTORES; i++) {
        status = el2go_rtp_add_keystore(ctx, &keystores[i]);
        TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup);
    }

    /* Remove all keystores */
    for (i = 0; i < EL2GO_RTP_MAX_KEYSTORES; i++) {
        status = el2go_rtp_remove_keystore(ctx, &keystores[i]);
        TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup);
    }

    status = el2go_rtp_add_keystore(ctx, &keystores[EL2GO_RTP_MAX_KEYSTORES]);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_SUCCESS, status);

cleanup:
    status = el2go_rtp_free(&ctx);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_SUCCESS, status);

exit:
    return test_status;
}

/**
 * @brief Test keystore removal when not found.
 *
 * Verifies that attempting to remove a keystore that was never added returns
 * a not found error, and that removing already-removed keystores returns an
 * invalid state error.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_el2go_rtp_keystore_remove_not_found(void *params)
{
    el2go_rtp_ctx_t *ctx = NULL;
    el2go_keystore_t keystores[EL2GO_RTP_MAX_KEYSTORES + 1] = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    bool test_status = true;
    size_t i = 0;

    (void)params;

    init_keystores(keystores, EL2GO_RTP_MAX_KEYSTORES + 1, 0x80000000);

    status = el2go_rtp_init(&ctx);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    for (i = 0; i < EL2GO_RTP_MAX_KEYSTORES; i++) {
        status = el2go_rtp_add_keystore(ctx, &keystores[i]);
        TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup);
    }

    status = el2go_rtp_remove_keystore(ctx, &keystores[EL2GO_RTP_MAX_KEYSTORES]);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_NOT_FOUND, status, cleanup);

    /* Remove all keystores */
    for (i = 0; i < EL2GO_RTP_MAX_KEYSTORES; i++) {
        status = el2go_rtp_remove_keystore(ctx, &keystores[i]);
        TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup);
    }

    /* Try to remove keystores that were already removed */
    for (i = 0; i < EL2GO_RTP_MAX_KEYSTORES; i++) {
        status = el2go_rtp_remove_keystore(ctx, &keystores[i]);
        TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_INVALID_STATE, status, cleanup);
    }

cleanup:
    status = el2go_rtp_free(&ctx);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_SUCCESS, status);

exit:
    return test_status;
}

/**
 * @brief Test keystore addition at maximum limit.
 *
 * Verifies that keystores can be added up to the maximum limit and that
 * attempting to add one more returns a resource limit error.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_el2go_rtp_keystore_add_max_limit(void *params)
{
    el2go_rtp_ctx_t *ctx = NULL;
    el2go_keystore_t keystores[EL2GO_RTP_MAX_KEYSTORES + 1] = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    bool test_status = true;
    size_t i = 0;

    (void)params;

    init_keystores(keystores, EL2GO_RTP_MAX_KEYSTORES + 1, 0x80000000);

    status = el2go_rtp_init(&ctx);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    /* Add maximum allowed keystores */
    for (i = 0; i < EL2GO_RTP_MAX_KEYSTORES; i++) {
        status = el2go_rtp_add_keystore(ctx, &keystores[i]);
        TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup);
    }

    status = el2go_rtp_add_keystore(ctx, &keystores[EL2GO_RTP_MAX_KEYSTORES]);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_RESOURCE_LIMIT, status);

cleanup:
    status = el2go_rtp_free(&ctx);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_SUCCESS, status);

exit:
    return test_status;
}

/**
 * @brief Test keystore retrieval by ID with NULL parameters.
 *
 * Verifies that passing @c NULL for the context or output pointer returns
 * an invalid parameter error.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_el2go_get_keystore_by_id_null_parameters(void *params)
{
    el2go_rtp_ctx_t *ctx = NULL;
    el2go_keystore_t *keystore = NULL;
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    bool test_status = true;

    (void)params;

    status = el2go_rtp_init(&ctx);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    /* Test NULL context */
    status = el2go_rtp_get_keystore_by_id(NULL, 0x80000000, &keystore);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_INVALID_PARAMETER, status, cleanup);

    /* Test NULL keystore pointer */
    status = el2go_rtp_get_keystore_by_id(ctx, 0x80000000, NULL);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_INVALID_PARAMETER, status, cleanup);

    /* Test both NULL */
    status = el2go_rtp_get_keystore_by_id(NULL, 0x80000000, NULL);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_INVALID_PARAMETER, status);

cleanup:
    status = el2go_rtp_free(&ctx);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_SUCCESS, status);

exit:
    return test_status;
}

/**
 * @brief Test successful keystore retrieval by ID.
 *
 * Verifies that all added keystores can be successfully retrieved by their
 * IDs and that the retrieved pointers match the original keystore addresses.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_el2go_get_keystore_by_id_success(void *params)
{
    el2go_rtp_ctx_t *ctx = NULL;
    el2go_keystore_t keystores[EL2GO_RTP_MAX_KEYSTORES] = { 0 };
    el2go_keystore_t *retrieved_keystore = NULL;
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    bool test_status = true;
    size_t i = 0;

    (void)params;

    init_keystores(keystores, EL2GO_RTP_MAX_KEYSTORES, 0x80000000);

    status = el2go_rtp_init(&ctx);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    /* Add all keystores */
    for (i = 0; i < EL2GO_RTP_MAX_KEYSTORES; i++) {
        status = el2go_rtp_add_keystore(ctx, &keystores[i]);
        TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup);
    }

    /* Retrieve each keystore by ID and verify */
    for (i = 0; i < EL2GO_RTP_MAX_KEYSTORES; i++) {
        status = el2go_rtp_get_keystore_by_id(ctx, keystores[i].id, &retrieved_keystore);
        TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup);
        TEST_ASSERT_NOT_NULL_GOTO(retrieved_keystore, cleanup);
        TEST_ASSERT_GOTO(keystores[i].id == retrieved_keystore->id, cleanup);
        TEST_ASSERT_PTR_EQUAL_GOTO(&keystores[i], retrieved_keystore, cleanup);
    }

cleanup:
    status = el2go_rtp_free(&ctx);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_SUCCESS, status);

exit:
    return test_status;
}

/**
 * @brief Test keystore retrieval by ID when not found.
 *
 * Verifies that attempting to retrieve a keystore from an empty context or
 * with a non-existent ID returns a not found error.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_el2go_get_keystore_by_id_not_found(void *params)
{
    el2go_rtp_ctx_t *ctx = NULL;
    el2go_keystore_t keystores[EL2GO_RTP_MAX_KEYSTORES] = { 0 };
    el2go_keystore_t *retrieved_keystore = NULL;
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    bool test_status = true;
    size_t i = 0;

    (void)params;

    init_keystores(keystores, EL2GO_RTP_MAX_KEYSTORES, 0x80000000);

    status = el2go_rtp_init(&ctx);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    /* Try to get keystore from empty context */
    status = el2go_rtp_get_keystore_by_id(ctx, 0x80000000, &retrieved_keystore);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_NOT_FOUND, status, cleanup);

    /* Add all keystores */
    for (i = 0; i < EL2GO_RTP_MAX_KEYSTORES; i++) {
        status = el2go_rtp_add_keystore(ctx, &keystores[i]);
        TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup);
    }

    /* Try to get keystore with non-existent ID */
    status = el2go_rtp_get_keystore_by_id(ctx, 0x99999999, &retrieved_keystore);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_NOT_FOUND, status);

cleanup:
    status = el2go_rtp_free(&ctx);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_SUCCESS, status);

exit:
    return test_status;
}

/**
 * @brief Test ID uniqueness enforcement between keystores and datastores.
 *
 * Verifies that a keystore and datastore cannot share the same ID, and that
 * the already exists error is returned when attempting to add a conflicting ID.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_el2go_rtp_keystore_datastore_id_conflict(void *params)
{
    el2go_rtp_ctx_t *ctx = NULL;
    el2go_keystore_t keystore = { 0 };
    el2go_datastore_t datastore = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    bool test_status = true;

    (void)params;

    /* Initialize with same ID */
    keystore.id = 0x50000000;
    datastore.id = 0x50000000;

    status = el2go_rtp_init(&ctx);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    status = el2go_rtp_add_keystore(ctx, &keystore);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup);

    status = el2go_rtp_add_datastore(ctx, &datastore);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_ALREADY_EXISTS, status, cleanup);

    status = el2go_rtp_remove_keystore(ctx, &keystore);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup);

    status = el2go_rtp_add_datastore(ctx, &datastore);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup);

    status = el2go_rtp_add_keystore(ctx, &keystore);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_ALREADY_EXISTS, status);

cleanup:
    status = el2go_rtp_free(&ctx);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_SUCCESS, status);

exit:
    return test_status;
}

/**
  * @brief Test el2go_rtp_datastore_el2go() with NULL parameters.
  *
  * Verifies that el2go_rtp_datastore_el2go() returns
  * EL2GO_STATUS_INVALID_PARAMETER when NULL is passed as the datastore,
  * keystore, config, or all three.
  *
  * @param params Unused.
  * @return @c true if all assertions pass, @c false otherwise.
  */
static bool test_el2go_rtp_datastore_el2go_null_parameters(void *params)
{
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    el2go_datastore_t datastore = { 0 };
    el2go_keystore_t keystore = { 0 };
    el2go_rtp_datastore_config_t config = { 0 };
    bool test_status = true;

    (void)params;

    /* Test NULL datastore */
    status = el2go_rtp_datastore_el2go(NULL, &keystore, &config);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_INVALID_PARAMETER, status, exit);

    /* Test NULL keystore */
    status = el2go_rtp_datastore_el2go(&datastore, NULL, &config);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_INVALID_PARAMETER, status, exit);

    /* Test NULL config */
    status = el2go_rtp_datastore_el2go(&datastore, &keystore, NULL);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_INVALID_PARAMETER, status, exit);

    /* Test all NULL */
    status = el2go_rtp_datastore_el2go(NULL, NULL, NULL);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_INVALID_PARAMETER, status);

exit:
    return test_status;
}

/**
 * @brief Register all public RTP tests with the test framework.
 *
 * Registers every test function in the order they should be executed.
 */
void register_el2go_rtp_tests(bool include_fs_tests)
{
    (void)include_fs_tests;
    TEST_REGISTER(test_el2go_rtp_init_and_free);
    TEST_REGISTER(test_el2go_rtp_null_parameters);
    TEST_REGISTER(test_el2go_rtp_datastore_add_remove_null_parameters);
    TEST_REGISTER(test_el2go_rtp_datastore_add_remove);
    TEST_REGISTER(test_el2go_rtp_datastore_remove_not_found);
    TEST_REGISTER(test_el2go_rtp_datastore_add_max_limit);
    TEST_REGISTER(test_el2go_get_datastore_by_id_null_parameters);
    TEST_REGISTER(test_el2go_get_datastore_by_id_success);
    TEST_REGISTER(test_el2go_get_datastore_by_id_not_found);
    TEST_REGISTER(test_el2go_rtp_datastore_el2go_null_parameters);
    TEST_REGISTER(test_el2go_rtp_keystore_add_remove_null_parameters);
    TEST_REGISTER(test_el2go_rtp_keystore_add_remove);
    TEST_REGISTER(test_el2go_rtp_keystore_remove_not_found);
    TEST_REGISTER(test_el2go_rtp_keystore_add_max_limit);
    TEST_REGISTER(test_el2go_get_keystore_by_id_null_parameters);
    TEST_REGISTER(test_el2go_get_keystore_by_id_success);
    TEST_REGISTER(test_el2go_get_keystore_by_id_not_found);
    TEST_REGISTER(test_el2go_rtp_keystore_datastore_id_conflict);

    /* el2go_rtp_provision tests */
    register_el2go_rtp_provision_tests(include_fs_tests);
}

/** @} */ /* end of test_el2go_rtp_public */
