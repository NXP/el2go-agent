/*
 * Copyright 2024-2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "el2go_import_blob.h"
#include "el2go_import_blob_validate.h"
#include "net_crypto.h"

void export_cert(size_t certificate_id)
{
    uint8_t cert_buffer[2048] = { 0U };
    uint8_t temp_buf[200] = { 0U };
    char subjectBuf[128] = { '\0' };
    char issuerBuf[128] = { '\0' };
    psa_status_t psa_status = PSA_SUCCESS;
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    size_t cert_len = 0U;
    size_t pub_key_len = 0U;

    psa_status = psa_export_key(certificate_id, cert_buffer, sizeof(cert_buffer), &cert_len);

    if (psa_status != PSA_SUCCESS) {
        LOG("\r\n Error in exporting the certificate! \r\n");
        goto cleanup;
    }

    LOG("Certificate in DER format: ");
    for (size_t i = 0; i < cert_len; i++) {
        LOG("%02X", *(cert_buffer + i));
    }
    LOG("\r\n");

    status = net_crypto_cert_get_dn(cert_buffer, cert_len, true, subjectBuf, sizeof(subjectBuf));
    if (status != EL2GO_STATUS_SUCCESS) {
        LOG("\r\n Error in parsing the client certificate \r\n");
        goto cleanup;
    }
    LOG("Subject field in certificate is:%s\r\n", subjectBuf);

    status = net_crypto_cert_get_dn(cert_buffer, cert_len, false, issuerBuf, sizeof(issuerBuf));
    if (status != EL2GO_STATUS_SUCCESS) {
        LOG("\r\n Error in getting the issuer field from certificate \r\n");
        goto cleanup;
    }
    LOG("Issuer field in certificate is:%s\r\n", issuerBuf);

    status =
        net_crypto_cert_get_pubkey(cert_buffer, cert_len, temp_buf, sizeof(temp_buf), &pub_key_len);
    if (status != EL2GO_STATUS_SUCCESS) {
        LOG(" \r\nError in extracting the public key from certificate \r\n");
        goto cleanup;
    }

    LOG("Public_key: ");
    for (size_t i = 0; i < pub_key_len; i++) {
        LOG("%02X", *(temp_buf + i));
    }
    LOG("\r\n");

cleanup:
    return;
}
