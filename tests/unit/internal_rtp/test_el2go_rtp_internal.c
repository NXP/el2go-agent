/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "osal.h"
#include "builtin_macros.h"

#include "rtp/el2go_rtp.h"
#include "rtp/el2go_rtp_config.h"

#include "common/el2go_platform.h"
#include "common/el2go_keystore.h"
#include "common/el2go_datastore.h"

#include "keystore_priv.h"
#include "plat_keys.h"
#include "net_crypto.h"

#include "pb.h"
#include "pb_decode.h"
#include "ServiceDescriptor.pb.h"

#include "el2go_service.h"
#include "el2go_server_connection.h"
#include "el2go_rtp_internal.h"

#include "test_framework.h"
#include "test_suites.h"
#include "test_utils.h"
#include "rtp_test_utils.h"
#include "test_el2go_service_internal.h"

/** @defgroup test_el2go_rtp_internal Internal RTP Tests
 * @brief Unit tests for the internal RTP module.
 *
 * Covers RTP context structure validation, datastore and keystore counter
 * tracking, and internal storage verification during add/remove operations.
 * @{
 */

/* ========================================================================== */
/* Malformed Datastore Test Helpers                                           */
/* ========================================================================== */
static el2go_status_t write_malformed_datastore(el2go_datastore_t *datastore, uint8_t *buffer,
                                                size_t total_size, config_data_hdr_t *header,
                                                bool correct_checksum)
{
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    size_t data_size = 0;
    size_t bytes_written = 0;

    if (correct_checksum) {
        /* Calculate correct checksum directly over buffer
         * (everything after the checksum field) */
        if (SUB_OVERFLOW(total_size, sizeof(header->checksum), &data_size)) {
            return EL2GO_STATUS_ARITHMETIC_OVERFLOW;
        }

        status = net_crypto_sha256(buffer + sizeof(header->checksum), data_size, header->checksum);
        if (status != EL2GO_STATUS_SUCCESS)
            return status;
    } else {
        /* Use zero checksum - will fail validation */
        memset(header->checksum, 0, sizeof(header->checksum));
    }

    /* Write header with checksum into buffer */
    memcpy(buffer, header, sizeof(*header));

    /* Write to datastore */
    status = el2go_datastore_allocate(datastore, total_size);
    if (status != EL2GO_STATUS_SUCCESS)
        return status;

    status = el2go_datastore_write(datastore, buffer, 0, total_size, &bytes_written);
    if (status != EL2GO_STATUS_SUCCESS)
        return status;

    return el2go_datastore_commit(datastore);
}

/* ========================================================================== */
/* Suite Setup                                                                 */
/* ========================================================================== */

static void suite_setup(void *params)
{
    (void)params;
    osal_lib_init();
}

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

    init_datastores(datastores, EL2GO_RTP_MAX_DATASTORES, 0x70000001);

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

    init_datastores(datastores, EL2GO_RTP_MAX_DATASTORES, 0x70000001);

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
 * @brief Test el2go_keystore_get_el2go_key_id() with NULL parameters.
 *
 * Verifies that el2go_keystore_get_el2go_key_id() returns
 * EL2GO_STATUS_INVALID_PARAMETER when NULL is passed as the keystore,
 * key_id, or both.
 */
static bool test_el2go_keystore_get_el2go_key_id_null_parameters(void *params)
{
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    el2go_keystore_t keystore = { 0 };
    uint32_t key_id = 0;
    bool test_status = true;

    (void)params;

    /* Test NULL keystore */
    status = el2go_keystore_get_el2go_key_id(NULL, &key_id);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_INVALID_PARAMETER, status, exit);

    /* Test NULL key_id */
    status = el2go_keystore_get_el2go_key_id(&keystore, NULL);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_INVALID_PARAMETER, status, exit);

    /* Test both NULL */
    status = el2go_keystore_get_el2go_key_id(NULL, NULL);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_INVALID_PARAMETER, status);

exit:
    return test_status;
}

/**
 * @brief Test el2go_keystore_get_el2go_key_id() successful retrieval.
 *
 * Verifies that el2go_keystore_get_el2go_key_id() returns
 * EL2GO_STATUS_SUCCESS and the expected EDGELOCK2GO_KEYID_ECC key ID
 * when called with a properly initialized keystore and platform context.
 */
static bool test_el2go_keystore_get_el2go_key_id_success(void *params)
{
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    el2go_keystore_t keystore = { 0 };
    el2go_platform_ctx_t *platform_ctx = NULL;
    uint32_t key_id = 0;
    bool test_status = true;

    (void)params;

    /* Initialize platform */
    status = el2go_platform_init(&platform_ctx);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    keystore.platform_ctx = platform_ctx;

    /* Get key ID - should return EDGELOCK2GO_KEYID_ECC */
    status = el2go_keystore_get_el2go_key_id(&keystore, &key_id);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup);
    TEST_ASSERT_EQUAL_GOTO(EDGELOCK2GO_KEYID_ECC, key_id, cleanup);

    TEST_PRINT_INFO("Got EL2GO key ID: 0x%08x", key_id);

cleanup:
    el2go_platform_free(&platform_ctx);

exit:
    return test_status;
}
/**
 * @brief Test el2go_keystore_get_el2go_cert() with NULL parameters.
 *
 * Verifies that el2go_keystore_get_el2go_cert() returns
 * EL2GO_STATUS_INVALID_PARAMETER when NULL is passed as the keystore,
 * cert buffer, or cert_len.
 */
static bool test_el2go_keystore_get_el2go_cert_null_parameters(void *params)
{
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    el2go_keystore_t keystore = { 0 };
    uint8_t cert[1024];
    size_t cert_len = sizeof(cert);
    bool test_status = true;

    (void)params;

    /* Test NULL keystore */
    status = el2go_keystore_get_el2go_cert(NULL, cert, &cert_len);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_INVALID_PARAMETER, status, exit);

    /* Test NULL cert */
    status = el2go_keystore_get_el2go_cert(&keystore, NULL, &cert_len);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_INVALID_PARAMETER, status, exit);

    /* Test NULL cert_len */
    status = el2go_keystore_get_el2go_cert(&keystore, cert, NULL);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_INVALID_PARAMETER, status);

exit:
    return test_status;
}

/**
 * @brief Test el2go_keystore_get_el2go_cert() when no certificate is available.
 *
 * Verifies that el2go_keystore_get_el2go_cert() returns
 * EL2GO_STATUS_CERT_NOT_AVAILABLE on the SMW platform, indicating that
 * the client certificate is not provisioned and a self-signed certificate
 * will be used as fallback.
 */
static bool test_el2go_keystore_get_el2go_cert_not_available(void *params)
{
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    el2go_keystore_t keystore = { 0 };
    el2go_platform_ctx_t *platform_ctx = NULL;
    uint8_t cert[EL2GO_RTP_CLIENT_CERT_MAX_SIZE];
    size_t cert_len = sizeof(cert);
    bool test_status = true;

    (void)params;

    /* Initialize platform */
    status = el2go_platform_init(&platform_ctx);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    keystore.platform_ctx = platform_ctx;

    /* SMW platform should return NOT_AVAILABLE */
    status = el2go_keystore_get_el2go_cert(&keystore, cert, &cert_len);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_CERT_NOT_AVAILABLE, status);

    TEST_PRINT_INFO("Platform certificate not available as expected - "
                    "will fall back to self-signed");

    el2go_platform_free(&platform_ctx);

exit:
    return test_status;
}
/**
 * @brief Test el2go_platform_get_el2go_key_id() with NULL parameters.
 *
 * Verifies that el2go_platform_get_el2go_key_id() returns
 * EL2GO_STATUS_INVALID_PARAMETER when NULL is passed as the platform
 * context, key_id, or both.
 */
static bool test_el2go_platform_get_el2go_key_id_null_parameters(void *params)
{
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    uint32_t key_id = 0;
    bool test_status = true;

    (void)params;

    /* Test NULL key_id */
    status = el2go_platform_get_el2go_key_id(NULL, NULL);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_INVALID_PARAMETER, status, exit);

    status = el2go_platform_get_el2go_key_id(NULL, &key_id);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_INVALID_PARAMETER, status);

exit:
    return test_status;
}

/**
 * @brief Test el2go_platform_get_el2go_key_id() successful retrieval.
 *
 * Verifies that el2go_platform_get_el2go_key_id() returns
 * EL2GO_STATUS_SUCCESS and the expected EDGELOCK2GO_KEYID_ECC key ID
 * when called with a properly initialized platform context.
 */
static bool test_el2go_platform_get_el2go_key_id_success(void *params)
{
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    el2go_platform_ctx_t *platform_ctx = NULL;
    uint32_t key_id = 0;
    bool test_status = true;

    (void)params;

    /* Initialize platform */
    status = el2go_platform_init(&platform_ctx);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    /* Get key ID */
    status = el2go_platform_get_el2go_key_id(platform_ctx, &key_id);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup);
    TEST_ASSERT_EQUAL_GOTO(EDGELOCK2GO_KEYID_ECC, key_id, cleanup);

    TEST_PRINT_INFO("Got EL2GO key ID from platform: 0x%08x", key_id);

cleanup:
    el2go_platform_free(&platform_ctx);

exit:
    return test_status;
}

/**
 * @brief Test el2go_platform_get_el2go_cert() when no certificate is available.
 *
 * Verifies that el2go_platform_get_el2go_cert() returns
 * EL2GO_STATUS_CERT_NOT_AVAILABLE on the SMW platform, indicating that
 * no platform certificate is provisioned.
 */
static bool test_el2go_platform_get_el2go_cert_not_available(void *params)
{
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    el2go_platform_ctx_t *platform_ctx = NULL;
    uint8_t cert[EL2GO_RTP_CLIENT_CERT_MAX_SIZE];
    size_t cert_len = sizeof(cert);
    bool test_status = true;

    (void)params;

    /* Initialize platform */
    status = el2go_platform_init(&platform_ctx);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    /* SMW platform should return NOT_AVAILABLE */
    status = el2go_platform_get_el2go_cert(platform_ctx, cert, &cert_len);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_CERT_NOT_AVAILABLE, status);

    TEST_PRINT_INFO("Platform certificate not available as expected");

    el2go_platform_free(&platform_ctx);

exit:
    return test_status;
}

/**
 * @brief Test el2go_rtp_datastore_el2go() with NULL parameters.
 *
 * Verifies that el2go_rtp_datastore_el2go() returns
 * EL2GO_STATUS_INVALID_PARAMETER when NULL is passed as the datastore,
 * keystore, config, or all three.
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
 * @brief Common helper for testing el2go_rtp_datastore_el2go() with a given hostname and port.
 *
 * Initializes a platform context, keystore, and plain datastore, then calls
 * el2go_rtp_datastore_el2go() with the provided hostname and port. Reads back
 * the written service descriptor and verifies that the hostname, port, client
 * certificate, server certificate, and client key SSS reference are all present
 * and correct. If hostname is NULL or port is zero, the compile-time defaults
 * are used and verified.
 *
 * @param hostname  The hostname to configure, or NULL to use the compile-time default.
 * @param port      The port to configure, or 0 to use the compile-time default.
 *
 * @return true if all assertions pass, false otherwise.
 */
static bool common_test_el2go_rtp_datastore_el2go(const char *hostname, uint16_t port)
{
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    el2go_datastore_t datastore = { 0 };
    el2go_keystore_t keystore = { 0 };
    el2go_platform_ctx_t *platform_ctx = NULL;
    el2go_rtp_datastore_config_t config = { 0 };
    nxp_iot_ServiceDescriptor service_descriptor = nxp_iot_ServiceDescriptor_init_default;
    const char *expected_hostname = hostname ? hostname : EL2GO_RTP_EDGELOCK2GO_HOSTNAME;
    uint16_t expected_port = port ? port : EL2GO_RTP_EDGELOCK2GO_PORT;
    size_t offset = 0;
    bool test_status = true;

    /* Initialize platform */
    status = el2go_platform_init(&platform_ctx);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    /* Initialize keystore with platform context */
    status = el2go_keystore_init(EL2GO_RTP_EDGELOCK2GO_KEYSTORE_ID, platform_ctx, &keystore);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup_platform);

    /* Initialize plain datastore */
    status = el2go_datastore_init(EL2GO_RTP_DATASTORE_EDGELOCK_ID, "test_el2go_ds",
                                  EL2GO_DATASTORE_TYPE_PLAIN, &datastore, NULL);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup_platform);

    /* Configure with provided hostname and port */
    config.hostname = hostname;
    config.port = port;
    config.certificate = NULL;

    /* Write EdgeLock 2GO connection data to datastore */
    status = el2go_rtp_datastore_el2go(&datastore, &keystore, &config);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup_datastore);

    TEST_PRINT_INFO("EdgeLock 2GO datastore written successfully");

    /* Read back the service descriptor and verify */
    status = srv_get_service_by_index(&datastore, 0, &offset, &service_descriptor);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup_datastore);

    /* Verify hostname */
    TEST_ASSERT_NOT_NULL_GOTO(service_descriptor.hostname, cleanup_datastore);
    TEST_ASSERT_EQUAL_GOTO(0, strcmp(service_descriptor.hostname, expected_hostname),
                           cleanup_datastore);
    TEST_PRINT_INFO("Hostname verified: %s", service_descriptor.hostname);

    /* Verify port */
    TEST_ASSERT_EQUAL_GOTO(true, service_descriptor.has_port, cleanup_datastore);
    TEST_ASSERT_EQUAL_GOTO(expected_port, service_descriptor.port, cleanup_datastore);
    TEST_PRINT_INFO("Port verified: %u", service_descriptor.port);

    /* Verify client certificate is present */
    TEST_ASSERT_NOT_NULL_GOTO(service_descriptor.client_certificate, cleanup_datastore);
    TEST_ASSERT_EQUAL_GOTO(true, service_descriptor.client_certificate->size > 0,
                           cleanup_datastore);
    TEST_PRINT_INFO("Client certificate size: %u bytes",
                    service_descriptor.client_certificate->size);

    /* Verify server certificate is present */
    TEST_ASSERT_NOT_NULL_GOTO(service_descriptor.server_certificate, cleanup_datastore);
    TEST_ASSERT_EQUAL_GOTO(true, service_descriptor.server_certificate->size > 0,
                           cleanup_datastore);
    TEST_PRINT_INFO("Server certificate size: %u bytes",
                    service_descriptor.server_certificate->size);

    /* Verify client key SSS reference */
    TEST_ASSERT_EQUAL_GOTO(true, service_descriptor.has_client_key_sss_ref, cleanup_datastore);
    TEST_PRINT_INFO("Client key object ID: 0x%08x",
                    service_descriptor.client_key_sss_ref.object_id);

    TEST_PRINT_INFO("All datastore fields verified successfully");

cleanup_datastore:
    pb_release(nxp_iot_ServiceDescriptor_fields, &service_descriptor);
    el2go_datastore_free(&datastore);

cleanup_platform:
    el2go_keystore_free(&keystore);
    el2go_platform_free(&platform_ctx);

exit:
    return test_status;
}

/**
 * @brief Test el2go_rtp_datastore_el2go() with compile-time default configuration.
 *
 * Verifies that el2go_rtp_datastore_el2go() correctly writes the EdgeLock 2GO
 * service descriptor to the datastore using the default hostname and port
 * defined at compile time when NULL hostname and zero port are provided.
 */
static bool test_el2go_rtp_datastore_el2go_default_config(void *params)
{
    (void)params;
    /* NULL hostname and 0 port will use compile-time defaults */
    return common_test_el2go_rtp_datastore_el2go(NULL, 0);
}

/**
 * @brief Test el2go_rtp_datastore_el2go() with a custom hostname and port.
 *
 * Verifies that el2go_rtp_datastore_el2go() correctly writes the EdgeLock 2GO
 * service descriptor to the datastore using a user-supplied hostname and port,
 * and that the stored values can be read back correctly.
 */
static bool test_el2go_rtp_datastore_el2go_custom_config(void *params)
{
    (void)params;
    return common_test_el2go_rtp_datastore_el2go("custom.el2go.example.com", 8443);
}

/**
 * @brief Test el2go_conn_datastore_needs_update() with matching and differing connection attributes.
 *
 * Verifies that el2go_conn_datastore_needs_update() returns false when the
 * stored hostname and port match the provided values, and returns true when
 * either the hostname, port, or both differ from the stored values.
 */
static bool test_el2go_rtp_datastore_needs_update(void *params)
{
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    el2go_datastore_t datastore = { 0 };
    el2go_keystore_t keystore = { 0 };
    el2go_platform_ctx_t *platform_ctx = NULL;
    el2go_rtp_datastore_config_t config = { 0 };
    bool needs_update = false;
    bool test_status = true;
    const char *hostname = "test.el2go.example.com";
    const uint16_t port = 8443;

    (void)params;

    /* Initialize platform */
    status = el2go_platform_init(&platform_ctx);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    /* Initialize keystore with platform context */
    status = el2go_keystore_init(EL2GO_RTP_EDGELOCK2GO_KEYSTORE_ID, platform_ctx, &keystore);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup_platform);

    /* Initialize plain datastore */
    status = el2go_datastore_init(EL2GO_RTP_DATASTORE_EDGELOCK_ID, "test_el2go_ds_update",
                                  EL2GO_DATASTORE_TYPE_PLAIN, &datastore, NULL);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup_platform);

    /* Configure with known hostname and port */
    config.hostname = hostname;
    config.port = port;
    config.certificate = NULL;

    /* Write EdgeLock 2GO connection data to datastore */
    status = el2go_rtp_datastore_el2go(&datastore, &keystore, &config);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup_datastore);

    TEST_PRINT_INFO("EdgeLock 2GO datastore written with %s:%u", hostname, port);

    /* Check with same hostname and port - should NOT need update */
    needs_update = el2go_conn_datastore_needs_update(&datastore, hostname, port, NULL);
    TEST_ASSERT_EQUAL_GOTO(false, needs_update, cleanup_datastore);
    TEST_PRINT_INFO("Same hostname/port: no update needed as expected");

    /* Check with different hostname - should need update */
    needs_update =
        el2go_conn_datastore_needs_update(&datastore, "different.el2go.example.com", port, NULL);
    TEST_ASSERT_EQUAL_GOTO(true, needs_update, cleanup_datastore);
    TEST_PRINT_INFO("Different hostname: update needed as expected");

    /* Check with different port - should need update */
    needs_update = el2go_conn_datastore_needs_update(&datastore, hostname, 9443, NULL);
    TEST_ASSERT_EQUAL_GOTO(true, needs_update, cleanup_datastore);
    TEST_PRINT_INFO("Different port: update needed as expected");

    /* Check with both different hostname and port - should need update */
    needs_update =
        el2go_conn_datastore_needs_update(&datastore, "different.el2go.example.com", 9443, NULL);
    TEST_ASSERT_EQUAL_CONTINUE(true, needs_update);
    TEST_PRINT_INFO("Different hostname and port: update needed as expected");

cleanup_datastore:
    el2go_datastore_free(&datastore);

cleanup_platform:
    el2go_keystore_free(&keystore);
    el2go_platform_free(&platform_ctx);

exit:
    return test_status;
}

/**
 * @brief Test el2go_conn_datastore_needs_update() with an incorrect service type.
 *
 * Verifies that el2go_conn_datastore_needs_update() returns true when the
 * datastore contains a service descriptor with a service type other than
 * EL2GOSERVICE, and returns false after el2go_rtp_datastore_el2go() rewrites
 * the datastore with the correct service type and connection attributes.
 */
static bool test_el2go_rtp_datastore_needs_update_service_type(void *params)
{
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    el2go_datastore_t datastore = { 0 };
    el2go_keystore_t keystore = { 0 };
    el2go_platform_ctx_t *platform_ctx = NULL;
    el2go_rtp_datastore_config_t config = { 0 };
    nxp_iot_ServiceDescriptor service_descriptor = nxp_iot_ServiceDescriptor_init_default;
    bool needs_update = false;
    bool test_status = true;
    const char *hostname = "test.el2go.example.com";
    const uint16_t port = 8443;
    size_t offset = 0;
    const nxp_iot_ServiceType invalid_service_type =
        (nxp_iot_ServiceType)(nxp_iot_ServiceType_EL2GOSERVICE + 1);

    (void)params;

    /* Initialize platform */
    status = el2go_platform_init(&platform_ctx);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    /* Initialize keystore with platform context */
    status = el2go_keystore_init(EL2GO_RTP_EDGELOCK2GO_KEYSTORE_ID, platform_ctx, &keystore);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup_platform);

    /* Initialize plain datastore */
    status = el2go_datastore_init(EL2GO_RTP_DATASTORE_EDGELOCK_ID, "test_el2go_ds_service_type",
                                  EL2GO_DATASTORE_TYPE_PLAIN, &datastore, NULL);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup_platform);

    /* Build a service descriptor with a different service type
     * Use an invalid/unknown service type to ensure needs_update returns true */
    service_descriptor.has_service_type = true;
    service_descriptor.service_type = invalid_service_type;
    service_descriptor.hostname = (char *)hostname;
    service_descriptor.has_port = true;
    service_descriptor.port = port;

    /* Add service descriptor with wrong service type using test utility */
    status = srv_add_service(&datastore, &service_descriptor);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup_datastore);

    TEST_PRINT_INFO("Datastore written with different service type");

    /* Verify the service type was written correctly by reading it back */
    service_descriptor = (nxp_iot_ServiceDescriptor)nxp_iot_ServiceDescriptor_init_default;

    status = srv_get_service_by_index(&datastore, 0, &offset, &service_descriptor);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup_datastore);
    TEST_ASSERT_EQUAL_GOTO(invalid_service_type, service_descriptor.service_type,
                           cleanup_datastore);
    TEST_PRINT_INFO("Service type verified: PSA");
    pb_release(nxp_iot_ServiceDescriptor_fields, &service_descriptor);
    service_descriptor = (nxp_iot_ServiceDescriptor)nxp_iot_ServiceDescriptor_init_default;

    /* Check needs update - should need update because service type is wrong */
    needs_update = el2go_conn_datastore_needs_update(&datastore, hostname, port, NULL);
    TEST_ASSERT_EQUAL_GOTO(true, needs_update, cleanup_datastore);
    TEST_PRINT_INFO("Update needed as expected - wrong service type");

    /* Now write the datastore with correct connection attributes */
    config.hostname = hostname;
    config.port = port;
    config.certificate = NULL;

    status = el2go_rtp_datastore_el2go(&datastore, &keystore, &config);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup_datastore);

    TEST_PRINT_INFO("Datastore written with correct connection attributes");

    /* Check needs update again - should NOT need update now */
    needs_update = el2go_conn_datastore_needs_update(&datastore, hostname, port, NULL);
    TEST_ASSERT_EQUAL_CONTINUE(false, needs_update);
    TEST_PRINT_INFO("No update needed - correct service type and attributes");

cleanup_datastore:
    pb_release(nxp_iot_ServiceDescriptor_fields, &service_descriptor);
    el2go_datastore_free(&datastore);

cleanup_platform:
    el2go_keystore_free(&keystore);
    el2go_platform_free(&platform_ctx);

exit:
    return test_status;
}

/**
 * @brief Test el2go_rtp_datastore_el2go() recovery from a datastore
 *        containing random data.
 *
 * Verifies that el2go_rtp_datastore_el2go() can recover from a datastore
 * containing arbitrary random data that fails both checksum validation and
 * service descriptor parsing. After recovery, the datastore is expected
 * to be valid and readable.
 */
static bool test_el2go_rtp_datastore_random_data(void *params)
{
    el2go_datastore_t datastore = { 0 };
    el2go_keystore_t keystore = { 0 };
    el2go_platform_ctx_t *platform_ctx = NULL;
    el2go_rtp_datastore_config_t config = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    nxp_iot_ServiceDescriptor sd = nxp_iot_ServiceDescriptor_init_default;
    size_t offset = 0;
    bool test_status = true;
    uint8_t random_data[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x12, 0x34, 0x56,
                              0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
                              0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00 };
    size_t bytes_written = 0;

    (void)params;

    /* Initialize platform and keystore */
    status = el2go_platform_init(&platform_ctx);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    status = el2go_keystore_init(EL2GO_RTP_EDGELOCK2GO_KEYSTORE_ID, platform_ctx, &keystore);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup_platform);

    status = el2go_datastore_init(EL2GO_RTP_DATASTORE_EDGELOCK_ID, "test_random_data",
                                  EL2GO_DATASTORE_TYPE_PLAIN, &datastore, NULL);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup_platform);

    /* Write random data directly into datastore */
    status = el2go_datastore_allocate(&datastore, sizeof(random_data));
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup_datastore);

    status = el2go_datastore_write(&datastore, random_data, 0, sizeof(random_data), &bytes_written);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup_datastore);

    status = el2go_datastore_commit(&datastore);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup_datastore);

    TEST_PRINT_INFO("Random data written to datastore");

    /* Try to validate - should fail with checksum error */
    status = srv_validate_configuration_data(&datastore);
    TEST_ASSERT_NOT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup_datastore);
    TEST_PRINT_INFO("Validation failed as expected: 0x%04x", status);

    /* Try to read services - should fail */
    status = srv_get_service_by_index(&datastore, 0, &offset, &sd);
    TEST_ASSERT_NOT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup_datastore);
    TEST_PRINT_INFO("Read service failed as expected: 0x%04x", status);
    pb_release(nxp_iot_ServiceDescriptor_fields, &sd);

    /* Now call el2go_rtp_datastore_el2go - should recover and succeed */
    config.hostname = NULL;
    config.port = 0;
    config.certificate = NULL;

    status = el2go_rtp_datastore_el2go(&datastore, &keystore, &config);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup_datastore);
    TEST_PRINT_INFO("el2go_rtp_datastore_el2go recovered successfully");

    /* Verify datastore is now valid */
    status = srv_validate_configuration_data(&datastore);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_SUCCESS, status);
    TEST_PRINT_INFO("Datastore is now valid after recovery");

cleanup_datastore:
    pb_release(nxp_iot_ServiceDescriptor_fields, &sd);
    el2go_datastore_free(&datastore);

cleanup_platform:
    el2go_keystore_free(&keystore);
    el2go_platform_free(&platform_ctx);

exit:
    return test_status;
}

/**
 * @brief Test el2go_rtp_datastore_el2go() recovery from a datastore with a
 *        malformed service payload and an incorrect checksum.
 *
 * Verifies that el2go_rtp_datastore_el2go() can recover from a datastore
 * that contains a valid-looking header with one service entry but a garbage
 * service payload and a zeroed checksum, causing both checksum validation
 * and service parsing to fail. After recovery, the datastore is expected
 * to be valid and readable.
 */
static bool test_el2go_rtp_datastore_malformed_services(void *params)
{
    el2go_datastore_t datastore = { 0 };
    el2go_keystore_t keystore = { 0 };
    el2go_platform_ctx_t *platform_ctx = NULL;
    el2go_rtp_datastore_config_t config = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    nxp_iot_ServiceDescriptor sd = nxp_iot_ServiceDescriptor_init_default;
    config_data_hdr_t header = { 0 };
    size_t offset = 0;
    bool test_status = true;
    uint8_t malformed_service[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
                                    0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0 };
    size_t total_size = sizeof(header) + sizeof(malformed_service);
    uint8_t *buffer = NULL;

    (void)params;

    /* Initialize platform and keystore */
    status = el2go_platform_init(&platform_ctx);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    status = el2go_keystore_init(EL2GO_RTP_EDGELOCK2GO_KEYSTORE_ID, platform_ctx, &keystore);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup_platform);

    status = el2go_datastore_init(EL2GO_RTP_DATASTORE_EDGELOCK_ID, "test_malformed_services",
                                  EL2GO_DATASTORE_TYPE_PLAIN, &datastore, NULL);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup_platform);

    buffer = osal_malloc(total_size);
    TEST_ASSERT_NOT_NULL_GOTO(buffer, cleanup_datastore);

    /* Build header with 1 service but garbage service data */
    header.number_of_services = 1;
    header.length = (uint32_t)total_size;
    header.version = EL2GO_CONFIGURATION_DATA_VERSION;

    memcpy(buffer, &header, sizeof(header));
    memcpy(buffer + sizeof(header), malformed_service, sizeof(malformed_service));

    /* Write with wrong checksum (zeros) */
    status = write_malformed_datastore(&datastore, buffer, total_size, &header, false);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup_datastore);

    TEST_PRINT_INFO("Malformed datastore written with wrong checksum");

    /* Validate - should fail with checksum error */
    status = srv_validate_configuration_data(&datastore);
    TEST_ASSERT_NOT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup_datastore);
    TEST_PRINT_INFO("Validation failed as expected: 0x%04x", status);

    /* Try to read services - should fail */
    status = srv_get_service_by_index(&datastore, 0, &offset, &sd);
    TEST_ASSERT_NOT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup_datastore);
    TEST_PRINT_INFO("Read service failed as expected: 0x%04x", status);
    pb_release(nxp_iot_ServiceDescriptor_fields, &sd);

    /* Now call el2go_rtp_datastore_el2go - should recover and succeed */
    config.hostname = NULL;
    config.port = 0;
    config.certificate = NULL;

    status = el2go_rtp_datastore_el2go(&datastore, &keystore, &config);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup_datastore);
    TEST_PRINT_INFO("el2go_rtp_datastore_el2go recovered successfully");

    /* Verify datastore is now valid */
    status = srv_validate_configuration_data(&datastore);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_SUCCESS, status);
    TEST_PRINT_INFO("Datastore is now valid after recovery");

cleanup_datastore:
    pb_release(nxp_iot_ServiceDescriptor_fields, &sd);
    if (buffer)
        osal_free(buffer);
    el2go_datastore_free(&datastore);

cleanup_platform:
    el2go_keystore_free(&keystore);
    el2go_platform_free(&platform_ctx);

exit:
    return test_status;
}

/**
 * @brief Test el2go_rtp_datastore_el2go() recovery from a datastore with a
 *        correct checksum but malformed service payload.
 *
 * Verifies that el2go_rtp_datastore_el2go() can recover from a datastore
 * that passes checksum validation but contains a garbage service payload
 * that cannot be decoded as a valid protobuf service descriptor.
 * After recovery, the datastore is expected to be valid and readable.
 */
static bool test_el2go_rtp_datastore_correct_checksum_malformed_services(void *params)
{
    el2go_datastore_t datastore = { 0 };
    el2go_keystore_t keystore = { 0 };
    el2go_platform_ctx_t *platform_ctx = NULL;
    el2go_rtp_datastore_config_t config = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    nxp_iot_ServiceDescriptor sd = nxp_iot_ServiceDescriptor_init_default;
    config_data_hdr_t header = { 0 };
    size_t offset = 0;
    bool test_status = true;
    uint8_t malformed_service[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
                                    0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0 };
    size_t total_size = sizeof(header) + sizeof(malformed_service);
    uint8_t *buffer = NULL;

    (void)params;

    /* Initialize platform and keystore */
    status = el2go_platform_init(&platform_ctx);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    status = el2go_keystore_init(EL2GO_RTP_EDGELOCK2GO_KEYSTORE_ID, platform_ctx, &keystore);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup_platform);

    status = el2go_datastore_init(EL2GO_RTP_DATASTORE_EDGELOCK_ID,
                                  "test_correct_checksum_malformed", EL2GO_DATASTORE_TYPE_PLAIN,
                                  &datastore, NULL);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup_platform);

    buffer = osal_malloc(total_size);
    TEST_ASSERT_NOT_NULL_GOTO(buffer, cleanup_datastore);

    /* Build header with 1 service but garbage service data */
    header.number_of_services = 1;
    header.length = (uint32_t)total_size;
    header.version = EL2GO_CONFIGURATION_DATA_VERSION;

    memcpy(buffer, &header, sizeof(header));
    memcpy(buffer + sizeof(header), malformed_service, sizeof(malformed_service));

    /* Write with correct checksum */
    status = write_malformed_datastore(&datastore, buffer, total_size, &header, true);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup_datastore);

    TEST_PRINT_INFO("Datastore written with correct checksum but malformed services");

    /* Validate - should succeed since checksum is correct */
    status = srv_validate_configuration_data(&datastore);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup_datastore);
    TEST_PRINT_INFO("Validation passed as expected - checksum is correct");

    /* Try to read services - should fail since service data is malformed */
    status = srv_get_service_by_index(&datastore, 0, &offset, &sd);
    TEST_ASSERT_NOT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup_datastore);
    TEST_PRINT_INFO("Read service failed as expected: 0x%04x", status);
    pb_release(nxp_iot_ServiceDescriptor_fields, &sd);

    /* Now call el2go_rtp_datastore_el2go - should recover and succeed */
    config.hostname = NULL;
    config.port = 0;
    config.certificate = NULL;

    status = el2go_rtp_datastore_el2go(&datastore, &keystore, &config);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup_datastore);
    TEST_PRINT_INFO("el2go_rtp_datastore_el2go recovered successfully");

    /* Verify datastore is now valid */
    status = srv_validate_configuration_data(&datastore);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_SUCCESS, status);
    TEST_PRINT_INFO("Datastore is now valid after recovery");

cleanup_datastore:
    pb_release(nxp_iot_ServiceDescriptor_fields, &sd);
    if (buffer)
        osal_free(buffer);
    el2go_datastore_free(&datastore);

cleanup_platform:
    el2go_keystore_free(&keystore);
    el2go_platform_free(&platform_ctx);

exit:
    return test_status;
}

/**
 * @brief Register all internal RTP tests with the test framework.
 *
 * Registers every test function in the order they should be executed.
 */
void register_el2go_rtp_tests(bool include_fs_tests)
{
    /* Set suite-level setup function */
    TEST_SET_SUITE_SETUP(suite_setup);

    TEST_REGISTER(test_el2go_rtp_context_structure);
    TEST_REGISTER(test_el2go_rtp_datastore_count);
    TEST_REGISTER(test_el2go_rtp_datastore_internal_storage);
    TEST_REGISTER(test_el2go_rtp_keystore_count);
    TEST_REGISTER(test_el2go_rtp_keystore_internal_storage);

    /* el2go_platform_get_el2go_key_id tests */
    TEST_REGISTER(test_el2go_platform_get_el2go_key_id_null_parameters);
    TEST_REGISTER(test_el2go_platform_get_el2go_key_id_success);

    /* el2go_platform_get_el2go_cert tests */
    TEST_REGISTER(test_el2go_platform_get_el2go_cert_not_available);

    /* el2go_keystore_get_el2go_key_id tests */
    TEST_REGISTER(test_el2go_keystore_get_el2go_key_id_null_parameters);
    TEST_REGISTER(test_el2go_keystore_get_el2go_key_id_success);

    /* el2go_keystore_get_el2go_cert tests */
    TEST_REGISTER(test_el2go_keystore_get_el2go_cert_null_parameters);
    TEST_REGISTER(test_el2go_keystore_get_el2go_cert_not_available);

    /* el2go_rtp_datastore_el2go tests */
    TEST_REGISTER(test_el2go_rtp_datastore_el2go_null_parameters);

    TEST_REGISTER(test_el2go_rtp_datastore_el2go_default_config);

    TEST_REGISTER(test_el2go_rtp_datastore_el2go_custom_config);

    /* el2go_conn_datastore_needs_update tests */
    TEST_REGISTER(test_el2go_rtp_datastore_needs_update);

    TEST_REGISTER(test_el2go_rtp_datastore_needs_update_service_type);

    /* Datastore corruption recovery tests */
    TEST_REGISTER(test_el2go_rtp_datastore_random_data);
    TEST_REGISTER(test_el2go_rtp_datastore_malformed_services);
    TEST_REGISTER(test_el2go_rtp_datastore_correct_checksum_malformed_services);

    /* el2go_service tests */
    register_el2go_service_tests(include_fs_tests);
}

/** @} */ /* end of test_el2go_rtp_internal */
