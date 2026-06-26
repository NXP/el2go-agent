/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "osal.h"
#include "debug.h"

#include <psa/internal_trusted_storage.h>

#include "cred/el2go_ota_cred.h"

el2go_status_t el2go_ota_prepare_client_credentials(el2go_platform_ctx_t *platform_ctx,
                                                    const el2go_ota_mtls_config_t *config,
                                                    uint8_t **cert_der, size_t *cert_der_len,
                                                    uint32_t *key_id)
{
    psa_storage_info_t info = { 0 };
    psa_status_t psa_status = PSA_SUCCESS;
    uint8_t *cert_buf = NULL;
    size_t actual_len = 0U;
    el2go_status_t status = EL2GO_STATUS_SUCCESS;

    /* Use client_cert_object_id as psa_storage_uid_t (lower 32 bits; upper = 0). */
    psa_storage_uid_t cert_uid = (psa_storage_uid_t)config->client_cert_object_id;

    EL2GO_DBG_TRACE_FUNCTION_CALL;

    /* platform_ctx is not needed by this provider — PSA ITS is accessed
     * directly via the PSA Storage API without a platform context. */
    (void)platform_ctx;

    /* ------------------------------------------------------------------
     * Step 1: Query the certificate size from PSA ITS.
     *         psa_its_get_info() returns the size without reading data,
     *         allowing an exact heap allocation.
     * ------------------------------------------------------------------ */
    psa_status = psa_its_get_info(cert_uid, &info);
    if (psa_status != PSA_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "[EL2GO OTA] psa_its_get_info failed for UID 0x%08" PRIx32 ": %d\n",
                         config->client_cert_object_id, (int)psa_status);
        status = EL2GO_STATUS_NET_CRYPTO_INVALID_CERT;
        goto cleanup;
    }

    if (info.size == 0U) {
        EL2GO_DBG_PRINTF(ERROR,
                         "[EL2GO OTA] Certificate at ITS UID 0x%08" PRIx32 " has zero size\n",
                         config->client_cert_object_id);
        status = EL2GO_STATUS_NET_CRYPTO_INVALID_CERT;
        goto cleanup;
    }

    EL2GO_DBG_PRINTF(INFO,
                     "[EL2GO OTA] Certificate found in PSA ITS (UID: 0x%08" PRIx32
                     ", size: %zu bytes)\n",
                     config->client_cert_object_id, info.size);

    /* ------------------------------------------------------------------
     * Step 2: Allocate a buffer and read the DER certificate from ITS.
     * ------------------------------------------------------------------ */
    cert_buf = osal_calloc(1U, info.size);
    if (!cert_buf) {
        EL2GO_DBG_PRINTF(ERROR, "[EL2GO OTA] Failed to allocate certificate buffer\n");
        status = EL2GO_STATUS_ALLOCATION_ERROR;
        goto cleanup;
    }

    psa_status = psa_its_get(cert_uid, 0U, /* offset — read from start */
                             info.size, cert_buf, &actual_len);
    if (psa_status != PSA_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "[EL2GO OTA] psa_its_get failed for UID 0x%08" PRIx32 ": %d\n",
                         config->client_cert_object_id, (int)psa_status);
        status = EL2GO_STATUS_NET_CRYPTO_INVALID_CERT;
        goto cleanup;
    }

    if (actual_len != info.size) {
        EL2GO_DBG_PRINTF(ERROR, "[EL2GO OTA] Certificate read truncated: expected %zu, got %zu\n",
                         info.size, actual_len);
        status = EL2GO_STATUS_NET_CRYPTO_INVALID_CERT;
        goto cleanup;
    }

    EL2GO_DBG_PRINTF(INFO, "[EL2GO OTA] Client certificate read from PSA ITS (%zu bytes)\n",
                     actual_len);

    /* ------------------------------------------------------------------
     * Step 3: Transfer ownership of the certificate buffer to the caller.
     *         The caller (el2go_ota_tls.c) is responsible for osal_free().
     *         Return the PSA key ID directly — no key material is exported.
     * ------------------------------------------------------------------ */
    *cert_der = cert_buf;
    *cert_der_len = actual_len;
    *key_id = config->client_key_object_id;

    EL2GO_DBG_PRINTF(INFO, "[EL2GO OTA] Client key ID: 0x%08" PRIx32 "\n",
                     config->client_key_object_id);

    cert_buf = NULL; /* ownership transferred — do not free in cleanup */

cleanup:
    if (cert_buf)
        osal_free(cert_buf);

    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}
