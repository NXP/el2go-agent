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
    el2go_status_t status = EL2GO_STATUS_SUCCESS;

    EL2GO_DBG_TRACE_API_CALL;

    if (!ctx) {
        EL2GO_DBG_PRINTF(ERROR, "[EL2GO OTA] ctx must not be NULL\n");
        return EL2GO_OTA_ERROR_INVALID_PARAM;
    }

    *ctx = NULL;

    if (!config) {
        EL2GO_DBG_PRINTF(ERROR, "[EL2GO OTA] config must not be NULL\n");
        return EL2GO_OTA_ERROR_INVALID_PARAM;
    }

    if (!config->hostname) {
        EL2GO_DBG_PRINTF(ERROR, "[EL2GO OTA] config->hostname must not be NULL\n");
        return EL2GO_OTA_ERROR_INVALID_PARAM;
    }

    if (config->port == 0U) {
        EL2GO_DBG_PRINTF(ERROR, "[EL2GO OTA] config->port must not be 0\n");
        return EL2GO_OTA_ERROR_INVALID_PARAM;
    }

    if (!config->server_ca_chain || config->server_ca_chain_size == 0U) {
        EL2GO_DBG_PRINTF(ERROR, "[EL2GO OTA] server_ca_chain must not be NULL "
                                "and server_ca_chain_size must be > 0\n");
        return EL2GO_OTA_ERROR_INVALID_PARAM;
    }

    c = osal_calloc(1U, sizeof(*c));
    if (!c) {
        EL2GO_DBG_PRINTF(ERROR, "[EL2GO OTA] Failed to allocate context\n");
        return EL2GO_OTA_ERROR_MEMORY;
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
        EL2GO_DBG_PRINTF(ERROR, "[EL2GO OTA] Platform init failed: %d\n", status);
        osal_free(c);
        return EL2GO_OTA_ERROR_MEMORY;
    }

    status = el2go_ota_tls_init(&c->tls_ctx, c->platform_ctx, config);
    if (status != EL2GO_STATUS_SUCCESS) {
        set_last_error(c, "TLS initialisation failed");
        el2go_platform_free(&c->platform_ctx);
        osal_free(c);
        if (status == EL2GO_STATUS_NET_CRYPTO_INVALID_CERT) {
            return EL2GO_OTA_ERROR_CERT_VERIFY;
        }
        if (status == EL2GO_STATUS_NET_CRYPTO_INVALID_KEY) {
            return EL2GO_OTA_ERROR_AUTH;
        }
        if (status == EL2GO_STATUS_ALLOCATION_ERROR) {
            return EL2GO_OTA_ERROR_MEMORY;
        }
        /* EL2GO_STATUS_NET_CRYPTO_CONFIG_FAILED and any other TLS setup
         * errors are not memory failures — report them as a handshake/
         * configuration error so the caller is not misled. */
        return EL2GO_OTA_ERROR_TLS_HANDSHAKE;
    }

    *ctx = c;

    EL2GO_DBG_PRINTF(INFO, "[EL2GO OTA] Initialized. Server: %s:%u\n", config->hostname,
                     (unsigned int)config->port);

    return EL2GO_OTA_SUCCESS;
}

__export el2go_ota_status_t el2go_ota_connect(el2go_ota_ctx_t *ctx)
{
    el2go_status_t status = EL2GO_STATUS_SUCCESS;

    EL2GO_DBG_TRACE_API_CALL;

    if (!ctx) {
        EL2GO_DBG_PRINTF(ERROR, "[EL2GO OTA] ctx must not be NULL\n");
        return EL2GO_OTA_ERROR_INVALID_PARAM;
    }

    if (ctx->connected) {
        EL2GO_DBG_PRINTF(VERBOSE, "[EL2GO OTA] Already connected\n");
        return EL2GO_OTA_SUCCESS;
    }

    status = el2go_ota_tls_connect(ctx->tls_ctx);
    if (status != EL2GO_STATUS_SUCCESS) {
        if (status == EL2GO_STATUS_NET_CRYPTO_HANDSHAKE_FAILED) {
            set_last_error(ctx, "TLS handshake failed");
            return EL2GO_OTA_ERROR_TLS_HANDSHAKE;
        }
        if (status == EL2GO_STATUS_NET_CRYPTO_INVALID_CERT) {
            set_last_error(ctx, "Server certificate verification failed");
            return EL2GO_OTA_ERROR_CERT_VERIFY;
        }
        if (status == EL2GO_STATUS_NET_CRYPTO_INVALID_KEY) {
            set_last_error(ctx, "Client authentication failed");
            return EL2GO_OTA_ERROR_AUTH;
        }
        set_last_error(ctx, "Network connection failed");
        return EL2GO_OTA_ERROR_NETWORK;
    }

    ctx->connected = true;
    ctx->last_error = "";

    EL2GO_DBG_PRINTF(INFO, "[EL2GO OTA] mTLS connection established\n");

    return EL2GO_OTA_SUCCESS;
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
