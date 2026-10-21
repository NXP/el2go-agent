/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <inttypes.h>

#include <psa/crypto.h>

#include "osal.h"
#include "debug.h"
#include "el2go_ota_cred.h"

el2go_status_t el2go_ota_prepare_client_credentials(el2go_platform_ctx_t *platform_ctx,
                                                    const el2go_ota_mtls_config_t *config,
                                                    uint8_t **cert_der, size_t *cert_der_len,
                                                    uint32_t *key_id)
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_status_t psa_status = PSA_ERROR_GENERIC_ERROR;
    uint8_t *cert_buf = NULL;
    size_t actual_len = 0U;
    size_t buf_size = 0U;
    psa_key_id_t cert_key_id = 0U;
    el2go_status_t status = EL2GO_STATUS_FAILURE;

    EL2GO_DBG_TRACE_API_CALL;

    if (!config || !cert_der || !cert_der_len || !key_id) {
        return EL2GO_STATUS_INVALID_PARAMETER;
    }

    /* Use client_cert_object_id as a PSA key ID. */
    cert_key_id = (psa_key_id_t)config->client_cert_object_id;

    /* platform_ctx is not needed by this provider — PSA crypto is accessed
     * directly via the PSA Crypto API without a platform context. */
    (void)platform_ctx;

    /* Step 1: Query the key attributes to determine the export buffer size. */
    psa_status = psa_get_key_attributes(cert_key_id, &attributes);
    if (psa_status != PSA_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "psa_get_key_attributes failed for key ID 0x%08" PRIx32 ": %d\n",
                         config->client_cert_object_id, (int)psa_status);
        status = EL2GO_STATUS_NET_CRYPTO_INVALID_CERT;
        goto cleanup;
    }

    buf_size =
        PSA_EXPORT_KEY_OUTPUT_SIZE(psa_get_key_type(&attributes), psa_get_key_bits(&attributes));
    psa_reset_key_attributes(&attributes);

    if (buf_size == 0U) {
        EL2GO_DBG_PRINTF(ERROR, "PSA export size for key ID 0x%08" PRIx32 " is zero\n",
                         config->client_cert_object_id);
        status = EL2GO_STATUS_NET_CRYPTO_INVALID_CERT;
        goto cleanup;
    }

    EL2GO_DBG_PRINTF(INFO,
                     "Certificate found in PSA keystore (key ID: 0x%08" PRIx32
                     ", export buf size: %zu bytes)\n",
                     config->client_cert_object_id, buf_size);

    /* Step 2: Allocate a buffer and export the certificate from the PSA keystore. */
    cert_buf = osal_calloc(1U, buf_size);
    if (!cert_buf) {
        EL2GO_DBG_PRINTF(ERROR, "Failed to allocate certificate buffer\n");
        status = EL2GO_STATUS_ALLOCATION_ERROR;
        goto cleanup;
    }

    psa_status = psa_export_key(cert_key_id, cert_buf, buf_size, &actual_len);
    if (psa_status != PSA_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "psa_export_key failed for key ID 0x%08" PRIx32 ": %d\n",
                         config->client_cert_object_id, (int)psa_status);
        status = EL2GO_STATUS_NET_CRYPTO_INVALID_CERT;
        goto cleanup;
    }

    if (actual_len == 0U) {
        EL2GO_DBG_PRINTF(ERROR, "psa_export_key returned zero bytes for key ID 0x%08" PRIx32 "\n",
                         config->client_cert_object_id);
        status = EL2GO_STATUS_NET_CRYPTO_INVALID_CERT;
        goto cleanup;
    }

    EL2GO_DBG_PRINTF(INFO, "Client certificate exported from PSA keystore (%zu bytes)\n",
                     actual_len);

    /* Step 3: Transfer ownership of the certificate buffer to the caller.
     *         The caller (el2go_ota_tls.c) is responsible for osal_free().
     *         Return the PSA key ID directly -- no key material is exported. */
    *cert_der = cert_buf;
    *cert_der_len = actual_len;
    *key_id = config->client_key_object_id;

    EL2GO_DBG_PRINTF(INFO, "Client key ID: 0x%08" PRIx32 "\n", config->client_key_object_id);

    status = EL2GO_STATUS_SUCCESS;
    cert_buf = NULL; /* ownership transferred -- do not free in cleanup */

cleanup:
    if (cert_buf)
        osal_free(cert_buf);

    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}
