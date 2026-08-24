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
#include "platform_defs.h"
#include "el2go_board.h"
#include "els_pkc_platform_priv.h"

struct el2go_platform_ctx {
    bool initialized;
};

__export el2go_status_t el2go_platform_init(el2go_platform_ctx_t **platform_ctx)
{
    el2go_platform_ctx_t *ctx = NULL;
    psa_status_t psa_status = PSA_ERROR_GENERIC_ERROR;
    el2go_status_t status = EL2GO_STATUS_FAILURE;

    EL2GO_DBG_TRACE_FUNCTION_CALL;

    if (!platform_ctx) {
        return EL2GO_STATUS_INVALID_PARAMETER;
    }

    /* Idempotent -- return immediately if already initialised. */
    if (*platform_ctx && (*platform_ctx)->initialized) {
        EL2GO_DBG_PRINTF(INFO, "[EL2GO ELS_PKC] Platform already initialized\n");
        return EL2GO_STATUS_SUCCESS;
    }

    el2go_board_init();

    ctx = osal_calloc(1U, sizeof(*ctx));
    if (!ctx) {
        EL2GO_DBG_PRINTF(ERROR, "[EL2GO ELS_PKC] Failed to allocate platform context\n");
        return EL2GO_STATUS_ALLOCATION_ERROR;
    }

    psa_status = psa_crypto_init();
    if (psa_status != PSA_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "[EL2GO ELS_PKC] psa_crypto_init failed: %d\n", (int)psa_status);
        status = EL2GO_STATUS_PLATFORM_INIT_FAILED;
        goto cleanup;
    }

    EL2GO_DBG_PRINTF(INFO, "[EL2GO ELS_PKC] PSA Crypto initialized\n");

    status = el2go_platform_register_el2go_key();
    if (status != EL2GO_STATUS_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "[EL2GO ELS_PKC] Failed to register EL2GO key: %d\n", (int)status);
        goto cleanup;
    }

    status = EL2GO_STATUS_SUCCESS; /* explicitly set before transferring ownership */
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
