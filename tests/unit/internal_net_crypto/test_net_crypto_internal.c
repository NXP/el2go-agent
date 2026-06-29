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

#include "plat_keys.h"
#include "platform_priv.h"
#include "net_crypto.h"
#include "common/el2go_platform.h"
#include "rtp/el2go_rtp_config.h"
#include "el2go_server_certificates.h"

#include "test_framework.h"
#include "test_utils.h"

/** @defgroup test_net_crypto_internal Internal Net Crypto Tests
 * @brief Unit tests for the internal net_crypto module.
 *
 * Covers context lifecycle, parameter validation, configuration,
 * certificate generation, read/write behaviour, cipher suite and
 * curve configuration, and live connection scenarios against the
 * EdgeLock 2GO server.
 * @{
 */

/** @brief Hostname used for all connection tests. */
#define TEST_HOSTNAME EL2GO_RTP_EDGELOCK2GO_HOSTNAME

/** @brief Port used for all connection tests. */
#define TEST_PORT EL2GO_RTP_EDGELOCK2GO_PORT

/** @brief Certificate subject used for client certificate generation. */
#define TEST_SUBJECT "CN=TestDevice,O=NXP"

/** @brief Trusted root CA certificates loaded from the RTP configuration. */
static const uint8_t trusted_root_ca_certs[] = { EL2GO_RTP_TRUSTED_ROOT_CA_CERTIFICATES };

/** @brief Size in bytes of @ref trusted_root_ca_certs. */
static const size_t trusted_root_ca_certs_size = EL2GO_RTP_TRUSTED_ROOT_CA_CERTIFICATES_SIZE;

/* ========================================================================== */
/* Suite Setup                                                                 */
/* ========================================================================== */

/**
 * @brief Suite-level setup function.
 *
 * Called once before the first test in the suite runs.
 * Initialises the OSAL library required by all tests.
 *
 * @param params Unused.
 */
static void suite_setup(void *params)
{
    (void)params;

    osal_lib_init();
}

/**
 * @brief Test basic context creation and cleanup.
 *
 * Verifies that a context can be successfully allocated and that it is
 * properly released and set to @c NULL when freed.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_net_crypto_context_lifecycle(void *params)
{
    net_crypto_ctx_t *ctx = NULL;
    el2go_status_t status = EL2GO_STATUS_SUCCESS;

    (void)params;

    /* Test context creation */
    status = net_crypto_new(&ctx);
    TEST_ASSERT_EQUAL(EL2GO_STATUS_SUCCESS, status);
    TEST_ASSERT_NOT_NULL(ctx);

    /* Test context cleanup */
    net_crypto_free(&ctx);
    TEST_ASSERT_NULL(ctx);

    return true;
}

/**
 * @brief Test NULL parameter handling across net_crypto functions.
 *
 * Verifies that passing @c NULL where a valid pointer is required returns
 * an invalid parameter error for context creation, configuration, certificate
 * setting, and key association.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_net_crypto_null_parameters(void *params)
{
    net_crypto_ctx_t *ctx = NULL;
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    bool test_status = true;

    (void)params;

    /* Test NULL context pointer */
    status = net_crypto_new(NULL);
    TEST_ASSERT_EQUAL(EL2GO_STATUS_INVALID_PARAMETER, status);

    /* Create valid context for further tests */
    status = net_crypto_new(&ctx);
    TEST_ASSERT_EQUAL(EL2GO_STATUS_SUCCESS, status);

    /* Test NULL parameters in various functions */
    status = net_crypto_configure(NULL, NULL);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_INVALID_PARAMETER, status, exit);

    status = net_crypto_set_server_cert(NULL, NULL, 0);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_INVALID_PARAMETER, status, exit);

    status = net_crypto_set_cli_cert(NULL, NULL, 0);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_INVALID_PARAMETER, status, exit);

    status = net_crypto_associate_key(NULL, 0);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_INVALID_PARAMETER, status, exit);

exit:
    /* Cleanup */
    net_crypto_free(&ctx);

    return test_status;
}

/**
 * @brief Test context configuration behaviour.
 *
 * Verifies that cipher suite and curve configuration fail before the context
 * is configured, succeed after a valid configuration is applied, and that
 * attempting to configure an already-configured context is rejected.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_net_crypto_configure(void *params)
{
    net_crypto_ctx_t *ctx = NULL;
    el2go_status_t status;
    net_crypto_config_t config = { .hostname = TEST_HOSTNAME, .port = TEST_PORT };
    el2go_cipher_list_t cipher_list = { .suites = NULL, .count = 0 };
    el2go_curve_list_t curve_list = { .curves = NULL, .count = 0 };
    bool test_status = true;

    (void)params;

    /* Create context */
    status = net_crypto_new(&ctx);
    TEST_ASSERT_EQUAL(EL2GO_STATUS_SUCCESS, status);

    /* Test that cipher suites fail before configuration */
    status = net_crypto_set_cipher_suites(ctx, &cipher_list);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_INVALID_PARAMETER, status, exit);

    /* Test that curves fail before configuration */
    status = net_crypto_set_curves(ctx, &curve_list);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_INVALID_PARAMETER, status, exit);

    /* Test valid configuration */
    status = net_crypto_configure(ctx, &config);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    /* Test that cipher suites succeed after configuration */
    status = net_crypto_set_cipher_suites(ctx, &cipher_list);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    /* Test that curves succeed after configuration */
    status = net_crypto_set_curves(ctx, &curve_list);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    /* Test that we can't configure twice */
    status = net_crypto_configure(ctx, &config);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_INVALID_PARAMETER, status);

exit:
    /* Cleanup */
    net_crypto_free(&ctx);
    return test_status;
}

/**
 * @brief Test self-signed certificate generation parameter validation.
 *
 * Initialises the platform to obtain the real device UUID, then verifies
 * that invalid parameter errors are returned when required inputs such as
 * the subject string, UUID buffer, or output buffer are @c NULL.
 *
 * @note Actual certificate generation requires a valid key in the keystore.
 *       This test validates parameter checking only.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_net_crypto_self_signed_cert(void *params)
{
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    uint8_t cert_buffer[2048];
    size_t cert_len = sizeof(cert_buffer);
    uint32_t test_key_id = 0x12345678;
    uint8_t *device_uuid = NULL;
    size_t device_uuid_len = 0;
    el2go_platform_ctx_t *platform_ctx = NULL;
    bool test_status = true;

    (void)params;

    /* Initialize platform to get UUID */
    status = el2go_platform_init(&platform_ctx);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    /* Get device UUID */
    status = el2go_platform_get_uuid(platform_ctx, &device_uuid, &device_uuid_len);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    TEST_PRINT_INFO("Retrieved device UUID (%zu bytes)", device_uuid_len);
    test_dump_hex("Device UUID", device_uuid, device_uuid_len);

    /* Test NULL parameters */
    status = net_crypto_self_signed_cert(NULL, test_key_id, device_uuid, device_uuid_len,
                                         cert_buffer, &cert_len);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_INVALID_PARAMETER, status, exit);

    status =
        net_crypto_self_signed_cert(TEST_SUBJECT, test_key_id, NULL, 0, cert_buffer, &cert_len);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_INVALID_PARAMETER, status, exit);

    status = net_crypto_self_signed_cert(TEST_SUBJECT, test_key_id, device_uuid, device_uuid_len,
                                         NULL, &cert_len);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_INVALID_PARAMETER, status);

exit:
    /* Cleanup */
    if (device_uuid)
        osal_free(device_uuid);
    if (platform_ctx)
        el2go_platform_free(&platform_ctx);

    return test_status;
}

/**
 * @brief Test read and write operations on a context that is not connected.
 *
 * Verifies that read and write operations fail when no connection has been
 * established, and also when called with @c NULL context or @c NULL buffer
 * pointers.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_net_crypto_read_write_not_connected(void *params)
{
    net_crypto_ctx_t *ctx = NULL;
    el2go_status_t status;
    net_crypto_config_t config = { .hostname = TEST_HOSTNAME, .port = TEST_PORT };
    uint8_t buffer[128];
    int ret;
    bool test_status = true;

    (void)params;

    /* Create and configure context */
    status = net_crypto_new(&ctx);
    TEST_ASSERT_EQUAL(EL2GO_STATUS_SUCCESS, status);

    status = net_crypto_configure(ctx, &config);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    /* Test read without connection - should fail */
    ret = net_crypto_read(ctx, buffer, sizeof(buffer));
    TEST_ASSERT_EQUAL_GOTO(-1, ret, exit);

    /* Test write without connection - should fail */
    ret = net_crypto_write(ctx, buffer, sizeof(buffer));
    TEST_ASSERT_EQUAL_GOTO(-1, ret, exit);

    /* Test NULL parameters */
    ret = net_crypto_read(NULL, buffer, sizeof(buffer));
    TEST_ASSERT_EQUAL_GOTO(-1, ret, exit);

    ret = net_crypto_write(NULL, buffer, sizeof(buffer));
    TEST_ASSERT_EQUAL_GOTO(-1, ret, exit);

    ret = net_crypto_read(ctx, NULL, sizeof(buffer));
    TEST_ASSERT_EQUAL_GOTO(-1, ret, exit);

    ret = net_crypto_write(ctx, NULL, sizeof(buffer));
    TEST_ASSERT_EQUAL_CONTINUE(-1, ret);

exit:
    /* Cleanup */
    net_crypto_free(&ctx);

    return test_status;
}

/**
 * @brief Test cipher suite and curve configuration.
 *
 * Verifies that both @c NULL and empty lists are accepted and fall back to
 * defaults, and that a @c NULL context is rejected with an invalid parameter
 * error for both cipher suite and curve configuration.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_net_crypto_cipher_suites(void *params)
{
    net_crypto_ctx_t *ctx = NULL;
    el2go_status_t status;
    net_crypto_config_t config = { .hostname = TEST_HOSTNAME, .port = TEST_PORT };
    el2go_cipher_list_t cipher_list = { .suites = NULL, .count = 0 };
    el2go_curve_list_t curve_list = { .curves = NULL, .count = 0 };
    bool test_status = true;

    (void)params;

    /* Create and configure context */
    status = net_crypto_new(&ctx);
    TEST_ASSERT_EQUAL(EL2GO_STATUS_SUCCESS, status);

    status = net_crypto_configure(ctx, &config);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    /* Test cipher suites with NULL list (should use defaults) */
    status = net_crypto_set_cipher_suites(ctx, NULL);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    /* Test cipher suites with empty list (should use defaults) */
    status = net_crypto_set_cipher_suites(ctx, &cipher_list);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    /* Test cipher suites with NULL context */
    status = net_crypto_set_cipher_suites(NULL, &cipher_list);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_INVALID_PARAMETER, status, exit);

    /* Test curves with NULL list (should use defaults) */
    status = net_crypto_set_curves(ctx, NULL);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    /* Test curves with empty list (should use defaults) */
    status = net_crypto_set_curves(ctx, &curve_list);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    /* Test curves with NULL context */
    status = net_crypto_set_curves(NULL, &curve_list);
    TEST_ASSERT_EQUAL_CONTINUE(EL2GO_STATUS_INVALID_PARAMETER, status);

exit:
    /* Cleanup */
    net_crypto_free(&ctx);

    return test_status;
}

/**
 * @brief Common helper for EL2GO live connection tests.
 *
 * Initialises the platform, retrieves the device UUID, creates and configures
 * a TLS context, optionally generates a self-signed client certificate, and
 * attempts a connection to the EdgeLock 2GO server.
 *
 * The hostname is read from the @c EL2GO_TEST_HOSTNAME environment variable;
 * if not set, @ref TEST_HOSTNAME is used as the default.
 *
 * @param subject        Certificate subject string, or @c NULL to skip client
 *                       certificate generation (no mTLS).
 * @param use_wrong_uuid If @c true, a hard-coded fake UUID is used instead of
 *                       the real device UUID, causing the server to reject the
 *                       client.
 * @param expect_success If @c true the connection must succeed; if @c false
 *                       the connection must fail.
 * @return @c true if the outcome matches @p expect_success, @c false otherwise.
 */
static bool test_net_crypto_el2go_connection_common(const char *subject, bool use_wrong_uuid,
                                                    bool expect_success)
{
    net_crypto_ctx_t *ctx = NULL;
    el2go_platform_ctx_t *platform_ctx = NULL;
    el2go_status_t status;
    const char *hostname = NULL;
    net_crypto_config_t config = { 0 };
    uint8_t client_cert[2048];
    size_t client_cert_len = sizeof(client_cert);
    uint32_t key_id = EDGELOCK2GO_KEYID_ECC;
    uint8_t *device_uuid = NULL;
    size_t device_uuid_len = 0;
    /* Fake UUID for unauthorized certificate test */
    uint8_t fake_uuid[16] = { 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
                              0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0 };
    uint8_t *cert_uuid = NULL;
    size_t cert_uuid_len = 0;
    bool test_status = true;

    /* Get hostname from environment variable, fallback to config default */
    hostname = getenv("EL2GO_TEST_HOSTNAME");
    if (!hostname) {
        hostname = TEST_HOSTNAME;
        TEST_PRINT_INFO("Using default hostname from config: %s", hostname);
    } else {
        TEST_PRINT_INFO("Using hostname from EL2GO_TEST_HOSTNAME: %s", hostname);
    }

    config.hostname = hostname;
    config.port = TEST_PORT;

    /* 1. Initialize platform (SMW) */
    status = el2go_platform_init(&platform_ctx);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup);

    /* 2. Get device UUID */
    status = el2go_platform_get_uuid(platform_ctx, &device_uuid, &device_uuid_len);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup);

    TEST_PRINT_INFO("Retrieved device UUID (%zu bytes)", device_uuid_len);
    test_dump_hex("Device UUID", device_uuid, device_uuid_len);

    /* Decide which UUID to use for certificate generation */
    if (use_wrong_uuid) {
        cert_uuid = fake_uuid;
        cert_uuid_len = sizeof(fake_uuid);
        TEST_PRINT_INFO("Using FAKE UUID for unauthorized certificate");
        test_dump_hex("Fake UUID", fake_uuid, sizeof(fake_uuid));
    } else {
        cert_uuid = device_uuid;
        cert_uuid_len = device_uuid_len;
    }

    /* 3. Create context and proceed */
    status = net_crypto_new(&ctx);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup);

    /* Configure connection */
    status = net_crypto_configure(ctx, &config);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup);

    TEST_PRINT_INFO("CA cert total size: %zu bytes", trusted_root_ca_certs_size);

    /* Set trusted root CA certificates for server verification */
    status = net_crypto_set_server_cert(ctx, trusted_root_ca_certs, trusted_root_ca_certs_size);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup);
    TEST_PRINT_INFO("Server certificates configured successfully");

    /* Generate self-signed client certificate if subject provided */
    if (subject) {
        status = net_crypto_self_signed_cert(subject, key_id, cert_uuid, cert_uuid_len, client_cert,
                                             &client_cert_len);
        if (status != EL2GO_STATUS_SUCCESS) {
            TEST_PRINT_ERROR("Failed to generate certificate: 0x%x", status);
            TEST_PRINT_ERROR("This is expected if no HSM key is available");
            test_status = false;
            goto cleanup;
        }
        TEST_PRINT_INFO("Self-signed client certificate generated (%zu bytes)", client_cert_len);

        /* Dump certificate for inspection */
        test_dump_hex("Client certificate DER", client_cert, client_cert_len);

        /* Set client certificate for mutual TLS authentication */
        status = net_crypto_set_cli_cert(ctx, client_cert, client_cert_len);
        TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup);
        TEST_PRINT_INFO("Client certificate configured successfully");

        /* Associate the private key from HSM */
        status = net_crypto_associate_key(ctx, key_id);
        if (status != EL2GO_STATUS_SUCCESS) {
            TEST_PRINT_ERROR("Failed to associate private key: 0x%x", status);
            TEST_PRINT_ERROR("This is expected if no HSM key is available");
            test_status = false;
            goto cleanup;
        }
        TEST_PRINT_INFO("Private key associated successfully");
    } else {
        TEST_PRINT_INFO("Skipping client certificate (testing without mTLS)");
    }

    /* Configure platform cipher suites */
    el2go_cipher_list_t cipher_list = el2go_platform_get_cipher_suites();

    status = net_crypto_set_cipher_suites(ctx, &cipher_list);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup);
    TEST_PRINT_INFO("Cipher suites configured successfully");

    /* Configure platform curves */
    el2go_curve_list_t curve_list = el2go_platform_get_curves();

    status = net_crypto_set_curves(ctx, &curve_list);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup);
    TEST_PRINT_INFO("Curves configured successfully");

    /* Attempt to connect */
    status = net_crypto_connect(ctx);

    if (expect_success) {
        /* We expect connection to succeed */
        if (status == EL2GO_STATUS_SUCCESS) {
            TEST_PRINT_INFO("Connection successful - testing disconnect");

            status = net_crypto_disconnect(ctx);
            TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, cleanup);

            TEST_PRINT_INFO("Disconnect successful");
        } else {
            TEST_PRINT_ERROR("Connection failed: 0x%x", status);
            test_status = false;
            goto cleanup;
        }
    } else {
        /* We expect connection to fail */
        if (status == EL2GO_STATUS_SUCCESS) {
            TEST_PRINT_ERROR("Connection succeeded when failure was expected!");

            /* Disconnect cleanly */
            status = net_crypto_disconnect(ctx);
            if (status != EL2GO_STATUS_SUCCESS) {
                TEST_PRINT_ERROR("Disconnect failed: 0x%x", status);
            }

            test_status = false;
            goto cleanup;
        } else {
            TEST_PRINT_INFO("Connection failed as expected: 0x%x", status);
        }
    }

cleanup:
    /* Cleanup */
    if (device_uuid)
        osal_free(device_uuid);
    if (ctx)
        net_crypto_free(&ctx);
    if (platform_ctx)
        el2go_platform_free(&platform_ctx);

    return test_status;
}

/**
 * @brief Test a live TLS connection to the EdgeLock 2GO server with proper certificates.
 *
 * Uses the real device UUID and a valid client certificate and expects the
 * connection to succeed.
 *
 * @param params Unused.
 * @return @c true if the connection succeeds, @c false otherwise.
 */
static bool test_net_crypto_el2go_connection(void *params)
{
    (void)params;
    return test_net_crypto_el2go_connection_common(TEST_SUBJECT, false, true);
}

/**
 * @brief Test connection failure when the client certificate contains a wrong UUID.
 *
 * Uses a fake UUID in the client certificate so that the server rejects it,
 * and expects the connection to fail.
 *
 * @param params Unused.
 * @return @c true if the connection fails as expected, @c false otherwise.
 */
static bool test_net_crypto_connect_wrong_client_cert(void *params)
{
    (void)params;
    return test_net_crypto_el2go_connection_common(TEST_SUBJECT, true, false);
}

/**
 * @brief Test connection failure when no client certificate is provided.
 *
 * Attempts a connection without a client certificate and expects the server
 * to reject it.
 *
 * @param params Unused.
 * @return @c true if the connection fails as expected, @c false otherwise.
 */
static bool test_net_crypto_connect_missing_client_cert(void *params)
{
    (void)params;
    return test_net_crypto_el2go_connection_common(NULL, false, false);
}

/**
 * @brief Test connection failure with an invalid hostname.
 *
 * Verifies that a connection attempt to an unresolvable hostname fails with
 * the expected error, that the context can be freed cleanly afterwards, and
 * that a new context can be created and configured successfully.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_net_crypto_connect_invalid_hostname(void *params)
{
    net_crypto_ctx_t *ctx = NULL;
    el2go_status_t status;
    net_crypto_config_t config = { .hostname = "invalid.hostname.that.does.not.exist.example.com",
                                   .port = 443 };
    bool test_status = true;

    (void)params;

    /* Create and configure context */
    status = net_crypto_new(&ctx);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    status = net_crypto_configure(ctx, &config);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    /* Attempt to connect - should fail */
    status = net_crypto_connect(ctx);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_NET_CRYPTO_CONNECT_FAILED, status, exit);

    TEST_PRINT_INFO("Connection failed as expected with invalid hostname");

    /* Verify we can still free the context without crash */
    net_crypto_free(&ctx);
    TEST_ASSERT_NULL_GOTO(ctx, exit);

    TEST_PRINT_INFO("Context freed successfully after connection failure");

    /* Create a new context to verify we can retry */
    status = net_crypto_new(&ctx);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    /* Configure with valid hostname this time */
    config.hostname = TEST_HOSTNAME;
    config.port = TEST_PORT;

    status = net_crypto_configure(ctx, &config);
    TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);

    TEST_PRINT_INFO("Successfully configured new context after previous failure");

exit:
    /* Cleanup */
    if (ctx)
        net_crypto_free(&ctx);

    return test_status;
}

/**
 * @brief Register all internal net_crypto tests with the test framework.
 *
 * Sets the suite-level setup function and registers every test function
 * in the order they should be executed.
 */
void register_net_crypto_tests(void)
{
    /* Set suite-level setup function */
    TEST_SET_SUITE_SETUP(suite_setup);

    TEST_REGISTER(test_net_crypto_context_lifecycle);
    TEST_REGISTER(test_net_crypto_null_parameters);
    TEST_REGISTER(test_net_crypto_configure);
    TEST_REGISTER(test_net_crypto_self_signed_cert);
    TEST_REGISTER(test_net_crypto_read_write_not_connected);
    TEST_REGISTER(test_net_crypto_cipher_suites);
    TEST_REGISTER(test_net_crypto_connect_invalid_hostname);
    TEST_REGISTER(test_net_crypto_el2go_connection);
    TEST_REGISTER(test_net_crypto_connect_wrong_client_cert);
    TEST_REGISTER(test_net_crypto_connect_missing_client_cert);
}

/** @} */ /* end of test_net_crypto_internal */
