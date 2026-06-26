/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <stddef.h>
#include <stdbool.h>

#include <psa/crypto.h>

#include "compiler.h"
#include "debug.h"
#include "osal.h"

#include "common/el2go_platform.h"
#include "platform_priv.h"

struct el2go_platform_ctx {
    bool initialized;
};

__export el2go_status_t el2go_platform_init(const el2go_platform_config_t *config,
                                            el2go_platform_ctx_t **platform_ctx)
{
    el2go_platform_ctx_t *ctx = NULL;
    psa_status_t psa_status = PSA_SUCCESS;
    el2go_status_t status = EL2GO_STATUS_SUCCESS;

    EL2GO_DBG_TRACE_FUNCTION_CALL;

    if (!config || !platform_ctx) {
        return EL2GO_STATUS_INVALID_PARAMETER;
    }

    /* Idempotent — return immediately if already initialised. */
    if (*platform_ctx && (*platform_ctx)->initialized) {
        EL2GO_DBG_PRINTF(INFO, "[EL2GO ELS_PKC] Platform already initialized\n");
        return EL2GO_STATUS_SUCCESS;
    }

    ctx = osal_calloc(1U, sizeof(*ctx));
    if (!ctx) {
        EL2GO_DBG_PRINTF(ERROR, "[EL2GO ELS_PKC] Failed to allocate platform context\n");
        return EL2GO_STATUS_ALLOCATION_ERROR;
    }

    /* ------------------------------------------------------------------
     * Initialise PSA Crypto.
     *
     * On RW61x + Zephyr (no TF-M), PSA Crypto is provided by mbedTLS
     * with the ELS PKC driver backing the S50 secure enclave.
     * psa_crypto_init() is idempotent per the PSA spec.
     * ------------------------------------------------------------------ */
    psa_status = psa_crypto_init();
    if (psa_status != PSA_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "[EL2GO ELS_PKC] psa_crypto_init failed: %d\n", (int)psa_status);
        status = EL2GO_STATUS_PLATFORM_INIT_FAILED;
        goto cleanup;
    }

    EL2GO_DBG_PRINTF(INFO, "[EL2GO ELS_PKC] PSA Crypto initialized\n");

    ctx->initialized = true;
    *platform_ctx = ctx;
    ctx = NULL; /* ownership transferred */

cleanup:
    if (ctx)
        osal_free(ctx);

    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}

__export el2go_status_t el2go_platform_free(el2go_platform_ctx_t **platform_ctx)
{
    EL2GO_DBG_TRACE_FUNCTION_CALL;

    if (!platform_ctx || !*platform_ctx) {
        return EL2GO_STATUS_INVALID_PARAMETER;
    }

    osal_free(*platform_ctx);
    *platform_ctx = NULL;

    EL2GO_DBG_PRINTF(INFO, "[EL2GO ELS_PKC] Platform context freed\n");
    return EL2GO_STATUS_SUCCESS;
}
