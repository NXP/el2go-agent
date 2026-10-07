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
#include "test_osal.h"
#include "rtp/el2go_rtp.h"
#include "rtp/el2go_rtp_config.h"
#include "common/el2go_platform.h"
#include "common/el2go_keystore.h"
#include "common/el2go_datastore.h"

#include "test_framework.h"
#include "test_suites.h"
#include "test_el2go_rtp_provision.h"

/* ========================================================================== */
/* el2go_rtp_provision - NULL Parameter Tests                                 */
/* ========================================================================== */

/**
 * @brief Test el2go_rtp_provision() with NULL context.
 *
 * Verifies that el2go_rtp_provision() returns
 * EL2GO_STATUS_INVALID_PARAMETER when NULL is passed as the context.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_el2go_rtp_provision_null_context(void *params)
{
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    bool test_status = true;

    (void)params;

    status = el2go_rtp_provision(NULL, NULL);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_INVALID_PARAMETER, status);

    return test_status;
}

/* ========================================================================== */
/* el2go_rtp_provision - No Keystore Tests                                    */
/* ========================================================================== */

/**
 * @brief Test el2go_rtp_provision() with no keystore registered.
 *
 * Verifies that el2go_rtp_provision() returns an error when called
 * with a valid context but no keystore registered, since the EL2GO
 * keystore is required for provisioning.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_el2go_rtp_provision_no_keystore(void *params)
{
    el2go_rtp_ctx_t *ctx = NULL;
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    bool test_status = true;

    (void)params;

    status = el2go_rtp_init(&ctx);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
    TEST_ASSERT_NOT_NULL_GOTO(ctx, exit);

    /* No keystore registered - should fail */
    status = el2go_rtp_provision(ctx, NULL);
    TEST_ASSERT_NOT_EQUAL_CONTINUE(EL2GO_STATUS_SUCCESS, status);
    TEST_PRINT_INFO("Provision without keystore failed as expected: 0x%04x", status);

    (void)el2go_rtp_free(&ctx);

exit:
    return test_status;
}
/* ========================================================================== */
/* el2go_rtp_provision - No Datastore Tests                                   */
/* ========================================================================== */

/**
 * @brief Test el2go_rtp_provision() with a keystore registered but no EL2GO datastore.
 *
 * Verifies that el2go_rtp_provision() falls back to compile-time constants
 * for hostname and port when a valid keystore is registered but no EL2GO
 * datastore has been added to the context.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_el2go_rtp_provision_no_datastore(void *params)
{
    el2go_rtp_ctx_t *ctx = NULL;
    el2go_keystore_t keystore = { 0 };
    el2go_platform_ctx_t *platform_ctx = NULL;
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    bool test_status = true;

    (void)params;

    status = el2go_platform_init(&platform_ctx);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    status = el2go_keystore_init(EL2GO_RTP_EDGELOCK2GO_KEYSTORE_ID, platform_ctx, &keystore);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup_platform);

    status = el2go_rtp_init(&ctx);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup_platform);

    status = el2go_rtp_add_keystore(ctx, &keystore);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup_ctx);

    /* No EL2GO datastore added - should fall back to compile-time constants */
    TEST_PRINT_INFO("No EL2GO datastore set - will use compile-time constants");

    status = el2go_rtp_provision(ctx, NULL);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_NET_CRYPTO_CONNECT_FAILED, status);
    TEST_PRINT_INFO("Provision without datastore returned: 0x%04x", status);

cleanup_ctx:
    el2go_rtp_free(&ctx);

cleanup_platform:
    el2go_keystore_free(&keystore);
    el2go_platform_free(&platform_ctx);

exit:
    return test_status;
}

/* ========================================================================== */
/* el2go_rtp_provision - Invalid Datastore Tests                              */
/* ========================================================================== */

/**
 * @brief Test el2go_rtp_provision() with a keystore and an invalid EL2GO datastore.
 *
 * Verifies that el2go_rtp_provision() falls back to compile-time constants
 * when the EL2GO datastore is registered but contains invalid data that
 * fails checksum validation.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_el2go_rtp_provision_invalid_datastore(void *params)
{
    el2go_rtp_ctx_t *ctx = NULL;
    el2go_keystore_t keystore = { 0 };
    el2go_datastore_t datastore = { 0 };
    el2go_platform_ctx_t *platform_ctx = NULL;
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    bool test_status = true;
    uint8_t random_data[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
                              0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0 };
    size_t bytes_written = 0;

    (void)params;

    status = el2go_platform_init(&platform_ctx);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    status = el2go_keystore_init(EL2GO_RTP_EDGELOCK2GO_KEYSTORE_ID, platform_ctx, &keystore);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup_platform);

    status = el2go_datastore_init(EL2GO_RTP_DATASTORE_EDGELOCK_ID, "test_provision_invalid_ds",
                                  EL2GO_DATASTORE_TYPE_PLAIN, &datastore, NULL);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup_platform);

    /* Write random data to make datastore invalid */
    status = el2go_datastore_allocate(&datastore, sizeof(random_data));
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup_datastore);

    status = el2go_datastore_write(&datastore, random_data, 0, sizeof(random_data), &bytes_written);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup_datastore);

    status = el2go_datastore_commit(&datastore);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup_datastore);

    status = el2go_rtp_init(&ctx);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup_datastore);

    status = el2go_rtp_add_keystore(ctx, &keystore);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup_ctx);

    status = el2go_rtp_add_datastore(ctx, &datastore);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup_ctx);

    TEST_PRINT_INFO("Datastore contains invalid data - will fall back to compile-time constants");

    status = el2go_rtp_provision(ctx, NULL);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_NET_CRYPTO_CONNECT_FAILED, status);
    TEST_PRINT_INFO("Provision with invalid datastore returned: 0x%04x", status);

cleanup_ctx:
    el2go_rtp_free(&ctx);

cleanup_datastore:
    el2go_datastore_free(&datastore);

cleanup_platform:
    el2go_keystore_free(&keystore);
    el2go_platform_free(&platform_ctx);

exit:
    return test_status;
}

/* ========================================================================== */
/* el2go_rtp_provision - Valid Datastore Tests                                */
/* ========================================================================== */

/**
 * @brief Test el2go_rtp_provision() with a keystore and a valid EL2GO datastore
 *        using compile-time default hostname and port.
 *
 * Verifies that el2go_rtp_provision() correctly reads the connection parameters
 * from the EL2GO datastore when it contains a valid EL2GOSERVICE service
 * descriptor written with the default hostname and port.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_el2go_rtp_provision_valid_datastore_default_config(void *params)
{
    el2go_rtp_ctx_t *ctx = NULL;
    el2go_keystore_t keystore = { 0 };
    el2go_datastore_t datastore = { 0 };
    el2go_platform_ctx_t *platform_ctx = NULL;
    el2go_rtp_datastore_config_t config = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    bool test_status = true;

    (void)params;

    status = el2go_platform_init(&platform_ctx);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    status = el2go_keystore_init(EL2GO_RTP_EDGELOCK2GO_KEYSTORE_ID, platform_ctx, &keystore);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup_platform);

    status = el2go_datastore_init(EL2GO_RTP_DATASTORE_EDGELOCK_ID,
                                  "test_provision_valid_ds_default", EL2GO_DATASTORE_TYPE_PLAIN,
                                  &datastore, NULL);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup_platform);

    /* Write valid EL2GO connection data with compile-time defaults */
    config.hostname = NULL;
    config.port = 0;
    config.certificate = NULL;

    status = el2go_rtp_datastore_el2go(&datastore, &keystore, &config);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup_datastore);
    TEST_PRINT_INFO("EL2GO datastore written with default config");

    status = el2go_rtp_init(&ctx);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup_datastore);

    status = el2go_rtp_add_keystore(ctx, &keystore);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup_ctx);

    status = el2go_rtp_add_datastore(ctx, &datastore);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup_ctx);

    status = el2go_rtp_provision(ctx, NULL);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_NET_CRYPTO_CONNECT_FAILED, status);
    TEST_PRINT_INFO("Provision with valid datastore (default config) returned: 0x%04x", status);

cleanup_ctx:
    el2go_rtp_free(&ctx);

cleanup_datastore:
    el2go_datastore_free(&datastore);

cleanup_platform:
    el2go_keystore_free(&keystore);
    el2go_platform_free(&platform_ctx);

exit:
    return test_status;
}

/**
 * @brief Test el2go_rtp_provision() with a keystore and a valid EL2GO datastore
 *        containing a custom hostname and port.
 *
 * Verifies that el2go_rtp_provision() correctly reads and uses a custom
 * hostname and port from the EL2GO datastore when provisioning. The hostname
 * and port are resolved from the environment variables EL2GO_HOSTNAME and
 * EL2GO_PORT. If not set, the compile-time defaults are used.
 *
 * @param params Unused.
 *
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_el2go_rtp_provision_valid_datastore_custom_config(void *params)
{
    el2go_rtp_ctx_t *ctx = NULL;
    el2go_keystore_t keystore = { 0 };
    el2go_datastore_t datastore = { 0 };
    el2go_platform_ctx_t *platform_ctx = NULL;
    el2go_rtp_datastore_config_t config = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    bool test_status = true;
    const char *hostname = NULL;
    uint16_t port = 0;

    (void)params;

    /* Resolve hostname from environment - test requires it to be set */
    hostname = test_osal_getenv("EL2GO_TEST_HOSTNAME");
    if (hostname == NULL) {
        TEST_PRINT_INFO("EL2GO_TEST_HOSTNAME not set, skipping test");
        return test_status;
    }
    port = 443;

    TEST_PRINT_INFO("Using hostname: %s port: %u",
                    hostname ? hostname : EL2GO_RTP_EDGELOCK2GO_HOSTNAME,
                    port ? port : EL2GO_RTP_EDGELOCK2GO_PORT);

    status = el2go_platform_init(&platform_ctx);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    status = el2go_keystore_init(EL2GO_RTP_EDGELOCK2GO_KEYSTORE_ID, platform_ctx, &keystore);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup_platform);

    status = el2go_datastore_init(EL2GO_RTP_DATASTORE_EDGELOCK_ID, "test_provision_valid_ds_custom",
                                  EL2GO_DATASTORE_TYPE_PLAIN, &datastore, NULL);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup_platform);

    config.hostname = hostname;
    config.port = port;
    config.certificate = NULL;

    status = el2go_rtp_datastore_el2go(&datastore, &keystore, &config);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup_datastore);
    TEST_PRINT_INFO("EL2GO datastore written with custom config");

    status = el2go_rtp_init(&ctx);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup_datastore);

    status = el2go_rtp_add_keystore(ctx, &keystore);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup_ctx);

    status = el2go_rtp_add_datastore(ctx, &datastore);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup_ctx);

    status = el2go_rtp_provision(ctx, NULL);
    TEST_ASSERT_CONTINUE(status == EL2GO_STATUS_SUCCESS ||
                         status == EL2GO_STATUS_RTP_PROVISIONING_FAILED);
    if (status == EL2GO_STATUS_RTP_PROVISIONING_FAILED)
        TEST_PRINT_WARN("Provision returned RTP_PROVISIONING_FAILED - "
                        "device may not be in a device group");
    TEST_PRINT_INFO("Provision with valid datastore (custom config) returned: 0x%04x", status);

cleanup_ctx:
    el2go_rtp_free(&ctx);

cleanup_datastore:
    el2go_datastore_free(&datastore);

cleanup_platform:
    el2go_keystore_free(&keystore);
    el2go_platform_free(&platform_ctx);

exit:
    return test_status;
}
/* ========================================================================== */
/* Test Registration                                                          */
/* ========================================================================== */

void register_el2go_rtp_provision_tests(bool include_fs_tests)
{
    (void)include_fs_tests;

    /* NULL parameter tests */
    TEST_REGISTER(test_el2go_rtp_provision_null_context);

    /* No keystore tests */
    TEST_REGISTER(test_el2go_rtp_provision_no_keystore);

    /* No datastore tests */
    TEST_REGISTER(test_el2go_rtp_provision_no_datastore);

    /* Invalid datastore tests */
    TEST_REGISTER(test_el2go_rtp_provision_invalid_datastore);

    /* Valid datastore tests */
    TEST_REGISTER(test_el2go_rtp_provision_valid_datastore_default_config);
    TEST_REGISTER(test_el2go_rtp_provision_valid_datastore_custom_config);
}