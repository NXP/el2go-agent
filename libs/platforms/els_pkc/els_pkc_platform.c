/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <stddef.h>
#include <stdbool.h>

#include <psa/crypto.h>

#if !defined(NXP_IOT_AGENT_HAVE_PSA_IMPL_TFM)
#include "mcuxClPsaDriver_Oracle_Interface_key_locations.h"
#include "mcuxClPsaDriver_Oracle_Utils.h"
// #include "mcuxClPsaDriver_Oracle_KeyRecipes.h"
#endif /* !NXP_IOT_AGENT_HAVE_PSA_IMPL_TFM */

#include "compiler.h"
#include "debug.h"
#include "osal.h"

#include "common/el2go_platform.h"
#include "platform_priv.h"
#include "platform_defs.h"

extern const key_recipe_t recipe_el2goconn_auth_prk;

struct el2go_platform_ctx {
    bool initialized;
};

#if !defined(NXP_IOT_AGENT_HAVE_PSA_IMPL_TFM)
static el2go_status_t el2go_platform_register_el2go_key(void)
{
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t id = 0U;
    psa_status_t psa_status;

    psa_set_key_algorithm(&attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attr, 256U);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_VERIFY_MESSAGE |
                                       PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_lifetime(&attr,
                         PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(
                             PSA_KEY_PERSISTENCE_DEFAULT,  // ← works: 0x3FFF0201 is in user range
                             PSA_KEY_LOCATION_S50_KEY_GEN_STORAGE));
    psa_set_key_id(&attr, EDGELOCK2GO_KEYID_ECC);  // 0x3FFF0201U

    psa_status =
        psa_import_key(&attr, (const uint8_t *)&recipe_el2goconn_auth_prk,
                       mcuxClPsaDriver_Oracle_Utils_GetRecipeSize(&recipe_el2goconn_auth_prk), &id);

    /* Key already persisted from a previous boot — not an error */
    if (psa_status == PSA_ERROR_ALREADY_EXISTS) {
        EL2GO_DBG_PRINTF(INFO, "[EL2GO ELS_PKC] EL2GO conn auth key already registered\n");
        return EL2GO_STATUS_SUCCESS;
    }

    if (psa_status != PSA_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "[EL2GO ELS_PKC] Failed to register EL2GO conn auth key: %d\n",
                         (int)psa_status);
        return EL2GO_STATUS_FAILURE;
    }

    EL2GO_DBG_PRINTF(INFO, "[EL2GO ELS_PKC] EL2GO conn auth key registered (ID=0x%08X)\n",
                     (unsigned)EDGELOCK2GO_KEYID_ECC);
    return EL2GO_STATUS_SUCCESS;
}
#endif /* !NXP_IOT_AGENT_HAVE_PSA_IMPL_TFM */

__export el2go_status_t el2go_platform_init(el2go_platform_ctx_t **platform_ctx)
{
    el2go_platform_ctx_t *ctx = NULL;
    psa_status_t psa_status = PSA_ERROR_GENERIC_ERROR;
    el2go_status_t status = EL2GO_STATUS_FAILURE;

    EL2GO_DBG_TRACE_FUNCTION_CALL;

    if (!platform_ctx) {
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

    psa_status = psa_crypto_init();
    if (psa_status != PSA_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "[EL2GO ELS_PKC] psa_crypto_init failed: %d\n", (int)psa_status);
        status = EL2GO_STATUS_PLATFORM_INIT_FAILED;
        goto cleanup;
    }

    EL2GO_DBG_PRINTF(INFO, "[EL2GO ELS_PKC] PSA Crypto initialized\n");

#if !defined(NXP_IOT_AGENT_HAVE_PSA_IMPL_TFM)
    status = el2go_platform_register_el2go_key();
    if (status != EL2GO_STATUS_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "[EL2GO ELS_PKC] Failed to register EL2GO key: %d\n", (int)status);
        goto cleanup;
    }
#endif /* !NXP_IOT_AGENT_HAVE_PSA_IMPL_TFM */

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
