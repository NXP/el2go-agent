/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <inttypes.h>

#include "osal.h"
#include "debug.h"

#include "net_crypto.h"
#include "plat_crypto_params.h"

#include "el2go_ota_tls.h"
#include "cred/el2go_ota_cred.h"

static const char *alpn_protos[] = { "h2", NULL };

/**
 * @brief Internal TLS context — wraps a net_crypto context.
 */
struct el2go_ota_tls_ctx {
    net_crypto_ctx_t *net_ctx; /**< Underlying net_crypto context. */
};

el2go_status_t el2go_ota_tls_init(el2go_ota_tls_ctx_t **out_ctx, el2go_platform_ctx_t *platform_ctx,
                                  const el2go_ota_mtls_config_t *config)
{
    el2go_ota_tls_ctx_t *ctx = NULL;
    net_crypto_config_t net_config = { 0 };
    el2go_cipher_list_t cipher_list = { 0 };
    el2go_curve_list_t curve_list = { 0 };
    uint8_t *client_cert = NULL;
    size_t client_cert_len = 0U;
    uint32_t key_id = 0U;
    el2go_status_t status = EL2GO_STATUS_FAILURE;

    EL2GO_DBG_TRACE_API_CALL;

    if (!out_ctx || !platform_ctx || !config) {
        return EL2GO_STATUS_INVALID_PARAMETER;
    }

    *out_ctx = NULL;

    /* Allocate and zero-initialise the wrapper context. */
    ctx = osal_calloc(1U, sizeof(*ctx));
    if (!ctx) {
        EL2GO_DBG_PRINTF(ERROR, "Failed to allocate TLS context\n");
        return EL2GO_STATUS_ALLOCATION_ERROR;
    }

    /* Step 1: Acquire client certificate and key ID.
     *         platform_ctx is owned and initialised by the caller
     *         (el2go_ota_init()). The implementation is selected at build
     *         time via EL2GO_OTA_CRED_PROVIDER. See el2go_ota_cred.h for
     *         available providers and how to add new ones. */
    status = el2go_ota_prepare_client_credentials(platform_ctx, config, &client_cert,
                                                  &client_cert_len, &key_id);
    if (status != EL2GO_STATUS_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "Failed to prepare client credentials: %d\n", status);
        goto cleanup;
    }

    /* Step 2: Allocate a new net_crypto context. */
    status = net_crypto_new(&ctx->net_ctx);
    if (status != EL2GO_STATUS_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "net_crypto_new failed: %d\n", status);
        goto cleanup;
    }

    /* Step 3: Configure the net_crypto context with server hostname/port. */
    net_config.hostname = config->hostname;
    net_config.port = config->port;

    status = net_crypto_configure(ctx->net_ctx, &net_config);
    if (status != EL2GO_STATUS_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "net_crypto_configure failed: %d\n", status);
        goto cleanup;
    }

    /* Step 4: Set the CA certificate chain for server verification. */
    status = net_crypto_set_server_cert(ctx->net_ctx, config->server_ca_chain,
                                        config->server_ca_chain_size);
    if (status != EL2GO_STATUS_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "net_crypto_set_server_cert failed: %d\n", status);
        goto cleanup;
    }

    EL2GO_DBG_PRINTF(INFO, "CA certificate configured (%zu bytes)\n", config->server_ca_chain_size);

    /* Step 5: Set the client certificate for mutual TLS.
     *         The buffer is freed after net_crypto parses it. */
    status = net_crypto_set_cli_cert(ctx->net_ctx, client_cert, client_cert_len);
    if (status != EL2GO_STATUS_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "net_crypto_set_cli_cert failed: %d\n", status);
        goto cleanup;
    }

    /* Step 6: Associate the private key.
     *         The key never leaves the platform keystore — net_crypto
     *         delegates signing to the platform during the TLS handshake. */
    status = net_crypto_associate_key(ctx->net_ctx, key_id);
    if (status != EL2GO_STATUS_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "net_crypto_associate_key failed: %d\n", status);
        goto cleanup;
    }

    EL2GO_DBG_PRINTF(INFO, "Client key associated (key ID: 0x%08" PRIx32 ")\n", key_id);

    /* Step 7: Configure platform cipher suites and curves. */
    cipher_list = el2go_platform_get_cipher_suites();
    status = net_crypto_set_cipher_suites(ctx->net_ctx, &cipher_list);
    if (status != EL2GO_STATUS_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "net_crypto_set_cipher_suites failed: %d\n", status);
        goto cleanup;
    }

    curve_list = el2go_platform_get_curves();
    status = net_crypto_set_curves(ctx->net_ctx, &curve_list);
    if (status != EL2GO_STATUS_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "net_crypto_set_curves failed: %d\n", status);
        goto cleanup;
    }

    /* ------------------------------------------------------------------
     * Step 8: Configure ALPN — server requires HTTP/2 (gRPC).
     * ------------------------------------------------------------------ */
    status = net_crypto_set_alpn(ctx->net_ctx, alpn_protos);
    if (status != EL2GO_STATUS_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "net_crypto_set_alpn failed: %d\n", status);
        goto cleanup;
    }

    status = EL2GO_STATUS_SUCCESS; /* explicitly set before transferring ownership */
    *out_ctx = ctx;
    ctx = NULL; /* ownership transferred — do not free in cleanup */

cleanup:
    /* Certificate buffer no longer needed once passed to net_crypto. */
    if (client_cert)
        osal_free(client_cert);

    if (ctx)
        el2go_ota_tls_deinit(ctx);

    if (status != EL2GO_STATUS_SUCCESS)
        *out_ctx = NULL;

    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}

el2go_status_t el2go_ota_tls_connect(el2go_ota_tls_ctx_t *ctx)
{
    el2go_status_t status = EL2GO_STATUS_FAILURE;

    EL2GO_DBG_TRACE_API_CALL;

    if (!ctx || !ctx->net_ctx) {
        EL2GO_DBG_PRINTF(ERROR, "el2go_ota_tls_connect: ctx must not be NULL\n");
        status = EL2GO_STATUS_INVALID_PARAMETER;
        goto exit;
    }

    status = net_crypto_connect(ctx->net_ctx);
    if (status != EL2GO_STATUS_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "net_crypto_connect failed: %d\n", status);
        goto exit;
    }

    EL2GO_DBG_PRINTF(INFO, "mTLS handshake complete\n");
    status = EL2GO_STATUS_SUCCESS;

exit:
    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}

void el2go_ota_tls_disconnect(el2go_ota_tls_ctx_t *ctx)
{
    el2go_status_t status = EL2GO_STATUS_FAILURE;

    EL2GO_DBG_TRACE_API_CALL;

    if (!ctx || !ctx->net_ctx)
        return;

    status = net_crypto_disconnect(ctx->net_ctx);
    if (status != EL2GO_STATUS_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "net_crypto_disconnect failed: %d\n", status);
    }

    EL2GO_DBG_PRINTF(INFO, "TLS connection closed\n");
}

void el2go_ota_tls_deinit(el2go_ota_tls_ctx_t *ctx)
{
    EL2GO_DBG_TRACE_API_CALL;

    if (!ctx)
        return;

    if (ctx->net_ctx)
        net_crypto_free(&ctx->net_ctx);

    osal_free(ctx);
}
