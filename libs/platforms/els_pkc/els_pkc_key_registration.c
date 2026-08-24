/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

/*
 * ELS PKC implementation of el2go_platform_register_el2go_key().
 *
 * Imports the EL2GO connection authentication key recipe into PSA so that
 * the S50 secure enclave can perform signing during the TLS handshake.
 * The key never leaves the hardware.
 *
 * This file is compiled only when NXP_IOT_AGENT_HAVE_PSA_IMPL_TFM is NOT
 * set. When TF-M is used, tfm/els_pkc_key_registration_tfm.c provides a
 * no-op stub instead.
 */

#include <psa/crypto.h>

#include "mcuxClPsaDriver_Oracle_Interface_key_locations.h"
#include "mcuxClPsaDriver_Oracle_Utils.h"

#include "debug.h"

#include "common/el2go_status.h"
#include "platform_defs.h"
#include "els_pkc_platform_priv.h"

extern const key_recipe_t recipe_el2goconn_auth_prk;

el2go_status_t el2go_platform_register_el2go_key(void)
{
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t id = 0U;
    psa_status_t psa_status;
    size_t recipe_size = 0u;

    psa_set_key_algorithm(&attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attr, 256U);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_VERIFY_MESSAGE |
                                       PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_lifetime(&attr,
                         PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(
                             PSA_KEY_PERSISTENCE_DEFAULT, PSA_KEY_LOCATION_S50_KEY_GEN_STORAGE));
    psa_set_key_id(&attr, EDGELOCK2GO_KEYID_ECC);

    psa_status =
        mcuxClPsaDriver_Oracle_Utils_GetRecipeSize(&recipe_el2goconn_auth_prk, &recipe_size);
    if (psa_status != PSA_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "[EL2GO ELS_PKC] Failed to get recipe size: %d\n", (int)psa_status);
        return EL2GO_STATUS_FAILURE;
    }

    psa_status =
        psa_import_key(&attr, (const uint8_t *)&recipe_el2goconn_auth_prk, recipe_size, &id);

    /* Key already persisted from a previous boot -- not an error. */
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
