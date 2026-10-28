/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <stdbool.h>
#include <string.h>

#include "osal.h"
#include "compiler.h"

#include "ota/el2go_ota_lib.h"
#include "common/el2go_version.h"
#include "common/el2go_platform.h"
#include "el2go_ota_tls.h"
#include "el2go_ota_transport.h"
#include "el2go_ota_download_engine.h"
#include "el2go_ota_status_reporting.h"
#include "debug.h"

/* Maximum total file entries cached across all updates/packages from check_for_updates(). */
#define EL2GO_OTA_MAX_CACHED_FILES \
    (EL2GO_OTA_MAX_UPDATES * EL2GO_OTA_MAX_PACKAGES * EL2GO_OTA_MAX_FILE_METADATA)

/*
 * Minimal internal cache entry: only the two fields needed for known_file_size
 * lookup (file_id + size).  Using the full el2go_ota_file_metadata_t would pull
 * in name/checksum fields and bloat the context by ~42 KB.
 * 72 bytes * 128 entries = 9,216 bytes total.
 */
typedef struct {
    char file_id[EL2GO_OTA_MAX_FILE_ID_LEN]; /**< Null-terminated file identifier. */
    int64_t size;                            /**< File size in bytes. */
} el2go_ota_file_size_cache_t;

struct el2go_ota_ctx {
    bool connected;                     /**< True when mTLS connection is open. */
    el2go_ota_tls_ctx_t *tls_ctx;       /**< Underlying TLS context. */
    el2go_platform_ctx_t *platform_ctx; /**< Platform context -- owned for lifetime of ctx. */
    el2go_ota_transport_t transport;    /**< Transport vtable -- initialised at connect time. */
    const char *hostname; /**< Server hostname -- points into user config (not owned). */
    el2go_ota_file_size_cache_t cached_files
        [EL2GO_OTA_MAX_CACHED_FILES]; /**< File size cache; populated by check_for_updates(). */
    size_t cached_file_count;         /**< Number of valid entries in cached_files[]. */
};

/**
 * @brief Map an internal el2go_status_t to the public el2go_ota_status_t.
 */
static el2go_ota_status_t map_status(el2go_status_t status)
{
    switch (status) {
    case EL2GO_STATUS_SUCCESS:
        return EL2GO_OTA_SUCCESS;
    case EL2GO_STATUS_NET_CRYPTO_INVALID_CERT:
        return EL2GO_OTA_ERROR_CERT_VERIFY;
    case EL2GO_STATUS_NET_CRYPTO_INVALID_KEY:
        return EL2GO_OTA_ERROR_AUTH;
    case EL2GO_STATUS_NET_CRYPTO_HANDSHAKE_FAILED:
        return EL2GO_OTA_ERROR_TLS_HANDSHAKE;
    case EL2GO_STATUS_NET_CRYPTO_CONFIG_FAILED:
        return EL2GO_OTA_ERROR_TLS_HANDSHAKE;
    case EL2GO_STATUS_ALLOCATION_ERROR:
        return EL2GO_OTA_ERROR_MEMORY;
    case EL2GO_STATUS_INVALID_PARAMETER:
        return EL2GO_OTA_ERROR_INVALID_PARAM;
    case EL2GO_STATUS_PLATFORM_INIT_FAILED:
        return EL2GO_OTA_ERROR_PLATFORM_INIT;
    default:
        return EL2GO_OTA_ERROR_NETWORK;
    }
}

__export el2go_ota_status_t el2go_ota_init(el2go_ota_ctx_t **ctx,
                                           const el2go_ota_mtls_config_t *config)
{
    el2go_ota_ctx_t *c = NULL;
    el2go_status_t status = EL2GO_STATUS_FAILURE;
    el2go_ota_status_t ota_status = EL2GO_OTA_ERROR_TLS_HANDSHAKE;

    EL2GO_DBG_TRACE_API_CALL;

    if (ctx == NULL) {
        EL2GO_DBG_PRINTF(ERROR, "ctx must not be NULL\n");
        ota_status = EL2GO_OTA_ERROR_INVALID_PARAM;
        goto exit;
    }

    *ctx = NULL;

    if (config == NULL) {
        EL2GO_DBG_PRINTF(ERROR, "config must not be NULL\n");
        ota_status = EL2GO_OTA_ERROR_INVALID_PARAM;
        goto exit;
    }

    if (config->hostname == NULL) {
        EL2GO_DBG_PRINTF(ERROR, "config->hostname must not be NULL\n");
        ota_status = EL2GO_OTA_ERROR_INVALID_PARAM;
        goto exit;
    }

    if (config->port == 0U) {
        EL2GO_DBG_PRINTF(ERROR, "config->port must not be 0\n");
        ota_status = EL2GO_OTA_ERROR_INVALID_PARAM;
        goto exit;
    }

    if (config->server_ca_chain == NULL || config->server_ca_chain_size == 0U) {
        EL2GO_DBG_PRINTF(ERROR, "server_ca_chain must not be NULL "
                                "and server_ca_chain_size must be > 0\n");
        ota_status = EL2GO_OTA_ERROR_INVALID_PARAM;
        goto exit;
    }

    c = osal_calloc(1U, sizeof(*c));
    if (c == NULL) {
        EL2GO_DBG_PRINTF(ERROR, "Failed to allocate context\n");
        ota_status = EL2GO_OTA_ERROR_MEMORY;
        goto exit;
    }

    status = el2go_platform_init(&c->platform_ctx);
    if (status != EL2GO_STATUS_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "Platform init failed: %d\n", status);
        ota_status = EL2GO_OTA_ERROR_PLATFORM_INIT;
        goto cleanup_context;
    }

    status = el2go_ota_tls_init(&c->tls_ctx, c->platform_ctx, config);
    if (status != EL2GO_STATUS_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "TLS initialisation failed: %d\n", status);
        ota_status = map_status(status);
        goto cleanup_platform;
    }

    /* Store hostname pointer -- config must remain valid for ctx lifetime. */
    c->hostname = config->hostname;
    *ctx = c;

    EL2GO_DBG_PRINTF(INFO, "Initialized. Server: %s:%u\n", config->hostname,
                     (unsigned int)config->port);

    ota_status = EL2GO_OTA_SUCCESS;
    goto exit;

cleanup_platform:
    el2go_platform_free(&c->platform_ctx);
cleanup_context:
    osal_free(c);
exit:
    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, ota_status);
    return ota_status;
}

__export el2go_ota_status_t el2go_ota_connect(el2go_ota_ctx_t *ctx)
{
    el2go_status_t status = EL2GO_STATUS_FAILURE;
    el2go_ota_status_t ota_status = EL2GO_OTA_ERROR_NETWORK;
    el2go_ota_status_t t_status = EL2GO_OTA_ERROR_NETWORK;

    EL2GO_DBG_TRACE_API_CALL;

    if (ctx == NULL) {
        EL2GO_DBG_PRINTF(ERROR, "ctx must not be NULL\n");
        ota_status = EL2GO_OTA_ERROR_INVALID_PARAM;
        goto exit;
    }

    if (ctx->connected) {
        EL2GO_DBG_PRINTF(VERBOSE, "Already connected\n");
        ota_status = EL2GO_OTA_SUCCESS;
        goto exit;
    }

    status = el2go_ota_tls_connect(ctx->tls_ctx);
    if (status != EL2GO_STATUS_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "TLS connect failed: %d\n", status);
        ota_status = map_status(status);
        goto exit;
    }

    t_status = el2go_ota_transport_init(&ctx->transport, ctx->tls_ctx, ctx->hostname);
    if (t_status != EL2GO_OTA_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "Transport init failed: %d\n", t_status);
        el2go_ota_tls_disconnect(ctx->tls_ctx);
        ota_status = t_status;
        goto exit;
    }

    ctx->connected = true;

    EL2GO_DBG_PRINTF(INFO, "mTLS connection established\n");
    ota_status = EL2GO_OTA_SUCCESS;

exit:
    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, ota_status);
    return ota_status;
}

__export el2go_ota_status_t el2go_ota_disconnect(el2go_ota_ctx_t *ctx)
{
    EL2GO_DBG_TRACE_API_CALL;

    if (ctx == NULL) {
        EL2GO_DBG_PRINTF(ERROR, "ctx must not be NULL\n");
        return EL2GO_OTA_ERROR_INVALID_PARAM;
    }

    if (!ctx->connected) {
        EL2GO_DBG_PRINTF(VERBOSE, "Not connected -- no-op\n");
        return EL2GO_OTA_SUCCESS;
    }

    if (ctx->transport.deinit != NULL) {
        ctx->transport.deinit(&ctx->transport);
    }

    el2go_ota_tls_disconnect(ctx->tls_ctx);
    ctx->connected = false;

    EL2GO_DBG_PRINTF(INFO, "Disconnected\n");

    return EL2GO_OTA_SUCCESS;
}

__export void el2go_ota_cleanup(el2go_ota_ctx_t **ctx)
{
    EL2GO_DBG_TRACE_API_CALL;

    if (ctx == NULL || *ctx == NULL) {
        return;
    }

    if ((*ctx)->connected) {
        if ((*ctx)->transport.deinit != NULL) {
            (*ctx)->transport.deinit(&(*ctx)->transport);
        }

        el2go_ota_tls_disconnect((*ctx)->tls_ctx);
        (*ctx)->connected = false;
    }

    el2go_ota_tls_deinit((*ctx)->tls_ctx);

    if ((*ctx)->platform_ctx != NULL)
        el2go_platform_free(&(*ctx)->platform_ctx);

    osal_free(*ctx);
    *ctx = NULL;

    EL2GO_DBG_PRINTF(INFO, "Cleaned up\n");
}

__export bool el2go_ota_is_connected(const el2go_ota_ctx_t *ctx)
{
    if (ctx == NULL) {
        return false;
    }
    return ctx->connected;
}

__export const char *el2go_ota_get_error_string(el2go_ota_status_t status)
{
    switch (status) {
    case EL2GO_OTA_SUCCESS:
        return "Success";
    case EL2GO_OTA_ERROR_INVALID_PARAM:
        return "Invalid parameter";
    case EL2GO_OTA_ERROR_MEMORY:
        return "Memory allocation failed";
    case EL2GO_OTA_ERROR_AUTH:
        return "Client authentication failed";
    case EL2GO_OTA_ERROR_NETWORK:
        return "Network connection failed";
    case EL2GO_OTA_ERROR_TLS_HANDSHAKE:
        return "TLS handshake failed";
    case EL2GO_OTA_ERROR_CERT_VERIFY:
        return "Server certificate verification failed";
    case EL2GO_OTA_ERROR_PLATFORM_INIT:
        return "Platform initialisation failed";
    case EL2GO_OTA_ERROR_ENCODE:
        return "Protobuf request encoding failed";
    case EL2GO_OTA_ERROR_DECODE:
        return "Protobuf response decoding failed";
    case EL2GO_OTA_ERROR_SERVER:
        return "Server returned a non-zero gRPC status code";
    case EL2GO_OTA_ERROR_INTERNAL:
        return "Unexpected internal error";
    default:
        return "Unknown error";
    }
}

__export el2go_ota_status_t el2go_ota_check_for_updates(el2go_ota_ctx_t *ctx,
                                                        const el2go_ota_attr_t *attrs,
                                                        size_t attr_count,
                                                        el2go_ota_check_update_resp_t *out_resp)
{
    EL2GO_DBG_TRACE_API_CALL;

    if (ctx == NULL) {
        EL2GO_DBG_PRINTF(ERROR, "ctx must not be NULL\n");
        return EL2GO_OTA_ERROR_INVALID_PARAM;
    }

    if (!ctx->connected) {
        EL2GO_DBG_PRINTF(ERROR, "not connected -- call el2go_ota_connect() first\n");
        return EL2GO_OTA_ERROR_NETWORK;
    }

    if (out_resp == NULL) {
        EL2GO_DBG_PRINTF(ERROR, "out_resp must not be NULL\n");
        return EL2GO_OTA_ERROR_INVALID_PARAM;
    }

    el2go_ota_status_t result =
        el2go_ota_download_engine_check_for_updates(&ctx->transport, attrs, attr_count, out_resp);
    if (result == EL2GO_OTA_SUCCESS) {
        /* Cache file metadata so download_package() can seed known_file_size upfront. */
        size_t cached = 0U;
        for (size_t u = 0U; u < out_resp->update_count && cached < EL2GO_OTA_MAX_CACHED_FILES;
             u++) {
            for (size_t p = 0U;
                 p < out_resp->updates[u].package_count && cached < EL2GO_OTA_MAX_CACHED_FILES;
                 p++) {
                for (size_t f = 0U; f < out_resp->updates[u].packages[p].file_count &&
                                    cached < EL2GO_OTA_MAX_CACHED_FILES;
                     f++) {
                    const el2go_ota_file_metadata_t *fm =
                        &out_resp->updates[u].packages[p].files[f];
                    (void)strncpy(ctx->cached_files[cached].file_id, fm->file_id,
                                  EL2GO_OTA_MAX_FILE_ID_LEN - 1U);
                    ctx->cached_files[cached].file_id[EL2GO_OTA_MAX_FILE_ID_LEN - 1U] = '\0';
                    ctx->cached_files[cached].size = fm->size;
                    cached++;
                }
            }
        }
        ctx->cached_file_count = cached;
    }
    return result;
}

__export el2go_ota_status_t el2go_ota_download_package(
    el2go_ota_ctx_t *ctx, const char *update_id, const char *package_id, const char *file_id,
    size_t resume_offset,
    el2go_ota_status_t (*chunk_cb)(const uint8_t *data, size_t len, size_t offset, void *cb_ctx),
    void *cb_ctx)
{
    EL2GO_DBG_TRACE_API_CALL;

    if (ctx == NULL) {
        EL2GO_DBG_PRINTF(ERROR, "ctx must not be NULL\n");
        return EL2GO_OTA_ERROR_INVALID_PARAM;
    }

    if (!ctx->connected) {
        EL2GO_DBG_PRINTF(ERROR, "not connected -- call el2go_ota_connect() first\n");
        return EL2GO_OTA_ERROR_NETWORK;
    }

    if (update_id == NULL || package_id == NULL || file_id == NULL || chunk_cb == NULL) {
        EL2GO_DBG_PRINTF(ERROR, "update_id, package_id, file_id, and chunk_cb must not be NULL\n");
        return EL2GO_OTA_ERROR_INVALID_PARAM;
    }

    /* Look up the cached file size from the most recent check_for_updates() response. */
    int64_t known_file_size = 0;
    for (size_t i = 0U; i < ctx->cached_file_count; i++) {
        if (strcmp(ctx->cached_files[i].file_id, file_id) == 0) {
            known_file_size = ctx->cached_files[i].size;
            break;
        }
    }

    return el2go_ota_download_engine_fetch_package(&ctx->transport, update_id, package_id, file_id,
                                                   resume_offset, known_file_size, chunk_cb,
                                                   cb_ctx);
}

__export el2go_ota_status_t el2go_ota_report_status(el2go_ota_ctx_t *ctx, const char *update_id,
                                                    const char *package_id,
                                                    el2go_ota_update_outcome_t outcome)
{
    EL2GO_DBG_TRACE_API_CALL;

    if (ctx == NULL) {
        EL2GO_DBG_PRINTF(ERROR, "ctx must not be NULL\n");
        return EL2GO_OTA_ERROR_INVALID_PARAM;
    }

    if (!ctx->connected) {
        EL2GO_DBG_PRINTF(ERROR, "not connected -- call el2go_ota_connect() first\n");
        return EL2GO_OTA_ERROR_NETWORK;
    }

    if (update_id == NULL || package_id == NULL) {
        EL2GO_DBG_PRINTF(ERROR, "update_id and package_id must not be NULL\n");
        return EL2GO_OTA_ERROR_INVALID_PARAM;
    }

    if (outcome != EL2GO_OTA_OUTCOME_SUCCESS && outcome != EL2GO_OTA_OUTCOME_FAILURE &&
        outcome != EL2GO_OTA_OUTCOME_ROLLBACK) {
        EL2GO_DBG_PRINTF(ERROR, "invalid outcome value: %d\n", (int)outcome);
        return EL2GO_OTA_ERROR_INVALID_PARAM;
    }

    return el2go_ota_status_reporting_report(&ctx->transport, update_id, package_id, outcome);
}

__export el2go_ota_status_t el2go_ota_schedule_status_report(const char *update_id,
                                                             const char *package_id,
                                                             el2go_ota_update_outcome_t outcome)
{
    EL2GO_DBG_TRACE_API_CALL;

    if (update_id == NULL || package_id == NULL) {
        EL2GO_DBG_PRINTF(ERROR, "update_id and package_id must not be NULL\n");
        return EL2GO_OTA_ERROR_INVALID_PARAM;
    }

    if (outcome != EL2GO_OTA_OUTCOME_SUCCESS && outcome != EL2GO_OTA_OUTCOME_FAILURE &&
        outcome != EL2GO_OTA_OUTCOME_ROLLBACK) {
        EL2GO_DBG_PRINTF(ERROR, "invalid outcome value: %d\n", (int)outcome);
        return EL2GO_OTA_ERROR_INVALID_PARAM;
    }

    return el2go_ota_status_reporting_schedule(update_id, package_id, outcome);
}

__export el2go_ota_status_t el2go_ota_get_pending_status(el2go_ota_pending_status_t *out)
{
    EL2GO_DBG_TRACE_API_CALL;

    if (out == NULL) {
        EL2GO_DBG_PRINTF(ERROR, "out must not be NULL\n");
        return EL2GO_OTA_ERROR_INVALID_PARAM;
    }

    return el2go_ota_status_reporting_read_pending(out);
}

__export el2go_ota_status_t el2go_ota_report_pending_status(el2go_ota_ctx_t *ctx)
{
    EL2GO_DBG_TRACE_API_CALL;

    if (ctx == NULL) {
        EL2GO_DBG_PRINTF(ERROR, "ctx must not be NULL\n");
        return EL2GO_OTA_ERROR_INVALID_PARAM;
    }

    if (!ctx->connected) {
        EL2GO_DBG_PRINTF(ERROR, "not connected -- call el2go_ota_connect() first\n");
        return EL2GO_OTA_ERROR_NETWORK;
    }

    return el2go_ota_status_reporting_retry_pending(&ctx->transport);
}

__export el2go_ota_status_t el2go_ota_get_version(unsigned int *major, unsigned int *minor,
                                                  unsigned int *patch)
{
    el2go_ota_status_t status = EL2GO_OTA_ERROR_INVALID_PARAM;

    EL2GO_DBG_TRACE_API_CALL;

    if (major == NULL || minor == NULL || patch == NULL)
        goto exit;

    *major = EL2GO_LIB_VERSION_MAJOR;
    *minor = EL2GO_LIB_VERSION_MINOR;
    *patch = EL2GO_LIB_VERSION_PATCH;

    status = EL2GO_OTA_SUCCESS;

exit:
    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}
