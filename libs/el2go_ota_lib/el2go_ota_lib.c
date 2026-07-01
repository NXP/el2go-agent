/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <stdbool.h>

#include "osal.h"
#include "compiler.h"
#include "debug.h"

#include "ota/el2go_ota_lib.h"
#include "common/el2go_platform.h"
#include "el2go_ota_tls.h"

struct el2go_ota_ctx {
    bool connected;                     /**< True when mTLS connection is open. */
    el2go_ota_tls_ctx_t *tls_ctx;       /**< Underlying TLS context. */
    el2go_platform_ctx_t *platform_ctx; /**< Platform context — owned for lifetime of ctx. */
    const char *last_error;             /**< Last error string (static literal). */
};

static void set_last_error(el2go_ota_ctx_t *ctx, const char *msg)
{
    ctx->last_error = msg;
    EL2GO_DBG_PRINTF(ERROR, "[EL2GO OTA] %s\n", msg);
}

__export el2go_ota_status_t el2go_ota_init(el2go_ota_ctx_t **ctx,
                                           const el2go_ota_mtls_config_t *config)
{
    el2go_ota_ctx_t *c = NULL;
    el2go_status_t status = EL2GO_STATUS_FAILURE;
    el2go_ota_status_t ota_status = EL2GO_OTA_ERROR_TLS_HANDSHAKE;

    EL2GO_DBG_TRACE_API_CALL;

    if (!ctx) {
        EL2GO_DBG_PRINTF(ERROR, "[EL2GO OTA] ctx must not be NULL\n");
        ota_status = EL2GO_OTA_ERROR_INVALID_PARAM;
        goto exit;
    }

    *ctx = NULL;

    if (!config) {
        EL2GO_DBG_PRINTF(ERROR, "[EL2GO OTA] config must not be NULL\n");
        ota_status = EL2GO_OTA_ERROR_INVALID_PARAM;
        goto exit;
    }

    if (!config->hostname) {
        EL2GO_DBG_PRINTF(ERROR, "[EL2GO OTA] config->hostname must not be NULL\n");
        ota_status = EL2GO_OTA_ERROR_INVALID_PARAM;
        goto exit;
    }

    if (config->port == 0U) {
        EL2GO_DBG_PRINTF(ERROR, "[EL2GO OTA] config->port must not be 0\n");
        ota_status = EL2GO_OTA_ERROR_INVALID_PARAM;
        goto exit;
    }

    if (!config->server_ca_chain || config->server_ca_chain_size == 0U) {
        EL2GO_DBG_PRINTF(ERROR, "[EL2GO OTA] server_ca_chain must not be NULL "
                                "and server_ca_chain_size must be > 0\n");
        ota_status = EL2GO_OTA_ERROR_INVALID_PARAM;
        goto exit;
    }

    c = osal_calloc(1U, sizeof(*c));
    if (!c) {
        EL2GO_DBG_PRINTF(ERROR, "[EL2GO OTA] Failed to allocate context\n");
        ota_status = EL2GO_OTA_ERROR_MEMORY;
        goto exit;
    }

    c->last_error = "";

    /* ------------------------------------------------------------------
     * Initialise the platform context (PSA crypto subsystem, secure
     * storage, etc.). Owned by the context for its full lifetime and
     * freed in el2go_ota_cleanup().
     * ------------------------------------------------------------------ */
    el2go_platform_config_t platform_config = { 0 };
    status = el2go_platform_init(&platform_config, &c->platform_ctx);
    if (status != EL2GO_STATUS_SUCCESS) {
        set_last_error(c, "Platform init failed");
        osal_free(c);
        c = NULL;
        ota_status = EL2GO_OTA_ERROR_PLATFORM_INIT;
        goto exit;
    }

    status = el2go_ota_tls_init(&c->tls_ctx, c->platform_ctx, config);
    if (status != EL2GO_STATUS_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "[EL2GO OTA] TLS initialisation failed: %d\n", status);
        el2go_platform_free(&c->platform_ctx);
        osal_free(c);
        c = NULL;
        /* Map internal status to public OTA status via ota_status var. */
        if (status == EL2GO_STATUS_NET_CRYPTO_INVALID_CERT) {
            ota_status = EL2GO_OTA_ERROR_CERT_VERIFY;
        } else if (status == EL2GO_STATUS_NET_CRYPTO_INVALID_KEY) {
            ota_status = EL2GO_OTA_ERROR_AUTH;
        } else if (status == EL2GO_STATUS_ALLOCATION_ERROR) {
            ota_status = EL2GO_OTA_ERROR_MEMORY;
        } else {
            /* EL2GO_STATUS_NET_CRYPTO_CONFIG_FAILED and any other TLS setup
             * errors — report as handshake/configuration error. */
            ota_status = EL2GO_OTA_ERROR_TLS_HANDSHAKE;
        }
        goto exit;
    }

    *ctx = c;

    EL2GO_DBG_PRINTF(INFO, "[EL2GO OTA] Initialized. Server: %s:%u\n", config->hostname,
                     (unsigned int)config->port);

    ota_status = EL2GO_OTA_SUCCESS;

exit:
    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, ota_status);
    return ota_status;
}

__export el2go_ota_status_t el2go_ota_connect(el2go_ota_ctx_t *ctx)
{
    el2go_status_t status = EL2GO_STATUS_FAILURE;            /* RC1: fail-safe default */
    el2go_ota_status_t ota_status = EL2GO_OTA_ERROR_NETWORK; /* RC1: fail-safe default */

    EL2GO_DBG_TRACE_API_CALL;

    if (!ctx) {
        EL2GO_DBG_PRINTF(ERROR, "[EL2GO OTA] ctx must not be NULL\n");
        ota_status = EL2GO_OTA_ERROR_INVALID_PARAM;
        goto exit;
    }

    if (ctx->connected) {
        EL2GO_DBG_PRINTF(VERBOSE, "[EL2GO OTA] Already connected\n");
        ota_status = EL2GO_OTA_SUCCESS;
        goto exit;
    }

    status = el2go_ota_tls_connect(ctx->tls_ctx);
    if (status != EL2GO_STATUS_SUCCESS) {
        /* RC3: Map via ota_status variable — no direct return literals. */
        if (status == EL2GO_STATUS_NET_CRYPTO_HANDSHAKE_FAILED) {
            set_last_error(ctx, "TLS handshake failed");
            ota_status = EL2GO_OTA_ERROR_TLS_HANDSHAKE;
        } else if (status == EL2GO_STATUS_NET_CRYPTO_INVALID_CERT) {
            set_last_error(ctx, "Server certificate verification failed");
            ota_status = EL2GO_OTA_ERROR_CERT_VERIFY;
        } else if (status == EL2GO_STATUS_NET_CRYPTO_INVALID_KEY) {
            set_last_error(ctx, "Client authentication failed");
            ota_status = EL2GO_OTA_ERROR_AUTH;
        } else {
            set_last_error(ctx, "Network connection failed");
            ota_status = EL2GO_OTA_ERROR_NETWORK;
        }
        goto exit;
    }

    ctx->connected = true;
    ctx->last_error = "";

    EL2GO_DBG_PRINTF(INFO, "[EL2GO OTA] mTLS connection established\n");
    ota_status = EL2GO_OTA_SUCCESS;

exit:
    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, ota_status);
    return ota_status;
}

__export el2go_ota_status_t el2go_ota_disconnect(el2go_ota_ctx_t *ctx)
{
    EL2GO_DBG_TRACE_API_CALL;

    if (!ctx) {
        EL2GO_DBG_PRINTF(ERROR, "[EL2GO OTA] ctx must not be NULL\n");
        return EL2GO_OTA_ERROR_INVALID_PARAM;
    }

    if (!ctx->connected) {
        EL2GO_DBG_PRINTF(VERBOSE, "[EL2GO OTA] Not connected — no-op\n");
        return EL2GO_OTA_SUCCESS;
    }

    el2go_ota_tls_disconnect(ctx->tls_ctx);
    ctx->connected = false;
    ctx->last_error = "";

    EL2GO_DBG_PRINTF(INFO, "[EL2GO OTA] Disconnected\n");

    return EL2GO_OTA_SUCCESS;
}

__export void el2go_ota_cleanup(el2go_ota_ctx_t **ctx)
{
    EL2GO_DBG_TRACE_API_CALL;

    if (!ctx || !*ctx) {
        return;
    }

    if ((*ctx)->connected) {
        el2go_ota_tls_disconnect((*ctx)->tls_ctx);
        (*ctx)->connected = false;
    }

    el2go_ota_tls_deinit((*ctx)->tls_ctx);

    if ((*ctx)->platform_ctx)
        el2go_platform_free(&(*ctx)->platform_ctx);

    osal_free(*ctx);
    *ctx = NULL;

    EL2GO_DBG_PRINTF(INFO, "[EL2GO OTA] Cleaned up\n");
}

__export bool el2go_ota_is_connected(const el2go_ota_ctx_t *ctx)
{
    if (!ctx) {
        return false;
    }
    return ctx->connected;
}

__export const char *el2go_ota_get_last_error(const el2go_ota_ctx_t *ctx)
{
    if (!ctx) {
        return "No context";
    }
    return ctx->last_error ? ctx->last_error : "";
}
