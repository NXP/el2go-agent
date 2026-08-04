/*
 * Copyright 2018-2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

/*
 * Pure-crypto subset of the mbedTLS net_crypto backend.
 *
 * Contains: SHA-256 (one-shot and streaming), certificate public-key
 *           extraction, DN extraction, and self-signed certificate generation.
 *
 * CSR generation lives in net_crypto_mbedtls_crypto_csr.c, which is
 * compiled only when PEM write support is available (MBEDTLS_CSR_ENABLED).
 *
 * None of these functions depend on the networking stack or the
 * mbedTLS SSL/TLS context.  This file is therefore compiled for
 * every build that has mbedTLS available, regardless of whether a
 * networking stack is present.
 *
 * The TLS/connection functions live in net_crypto_mbedtls_tls.c.
 */

#include <string.h>
#include <stdlib.h>

#include <mbedtls/x509.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/pk.h>
#include <mbedtls/error.h>

#include "builtin_macros.h"
#include "osal.h"
#include "debug.h"

#include "net_crypto.h"

#include "crypto/mbedtls_compat_crypto.h"

/** Chunk size for SHA-256 streaming operations */
#define NET_CRYPTO_SHA256_CHUNK_SIZE 64

el2go_status_t net_crypto_sha256_stream(net_crypto_fetch_callback_t fetch_callback, void *context,
                                        uint8_t *hash_out)
{
    mbedtls_compat_sha256_context sha_ctx = { 0 };
    uint8_t buffer[NET_CRYPTO_SHA256_CHUNK_SIZE] = { 0 };
    size_t bytes_read = 0;
    el2go_status_t status = EL2GO_STATUS_INVALID_PARAMETER;
    int ret = 0;

    EL2GO_DBG_TRACE_FUNCTION_CALL;

    if (!fetch_callback || !hash_out)
        goto exit;

    mbedtls_compat_sha256_init(&sha_ctx);

    ret = mbedtls_compat_sha256_starts(&sha_ctx);
    if (ret != 0) {
        EL2GO_DBG_PRINTF(ERROR, "SHA-256 init failed: -0x%04x\n", -ret);
        status = EL2GO_STATUS_NET_CRYPTO_SHA_ERROR;
        goto exit;
    }

    /* Process data in chunks */
    do {
        status = fetch_callback(context, buffer, NET_CRYPTO_SHA256_CHUNK_SIZE, &bytes_read);
        if (status != EL2GO_STATUS_SUCCESS) {
            EL2GO_DBG_PRINTF(ERROR, "Fetch callback failed: 0x%04x\n", status);
            goto exit;
        }

        if (bytes_read > 0) {
            ret = mbedtls_compat_sha256_update(&sha_ctx, buffer, bytes_read);
            if (ret != 0) {
                EL2GO_DBG_PRINTF(ERROR, "SHA-256 update err: -0x%04x\n", -ret);
                status = EL2GO_STATUS_NET_CRYPTO_SHA_ERROR;
                goto exit;
            }
        }
    } while (bytes_read > 0);

    /* Finalize hash */
    ret = mbedtls_compat_sha256_finish(&sha_ctx, hash_out);
    if (ret != 0) {
        EL2GO_DBG_PRINTF(ERROR, "SHA-256 finish failed: -0x%04x\n", -ret);
        status = EL2GO_STATUS_NET_CRYPTO_SHA_ERROR;
        goto exit;
    }

    EL2GO_DBG_PRINTF(VERBOSE, "SHA-256 hash calculated successfully\n");
    status = EL2GO_STATUS_SUCCESS;

exit:
    mbedtls_compat_sha256_free(&sha_ctx);
    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}

el2go_status_t net_crypto_sha256(const uint8_t *data, size_t data_len, uint8_t *hash_out)
{
    int ret = 0;
    el2go_status_t status = EL2GO_STATUS_INVALID_PARAMETER;

    EL2GO_DBG_TRACE_FUNCTION_CALL;

    if (!data || !hash_out)
        goto exit;

    ret = mbedtls_compat_sha256(data, data_len, hash_out);
    if (ret != 0) {
        EL2GO_DBG_PRINTF(ERROR, "SHA-256 calculation failed: -0x%04x\n", -ret);
        status = EL2GO_STATUS_NET_CRYPTO_SHA_ERROR;
        goto exit;
    }

    status = EL2GO_STATUS_SUCCESS;

exit:
    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}

el2go_status_t net_crypto_cert_get_pubkey(const uint8_t *cert_der, size_t cert_der_len,
                                          uint8_t *pubkey_out, size_t pubkey_out_size,
                                          size_t *pubkey_len)
{
    int ret = 0;
    mbedtls_x509_crt cert = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;

    EL2GO_DBG_TRACE_FUNCTION_CALL;

    if (!cert_der || !cert_der_len || !pubkey_out || !pubkey_out_size || !pubkey_len)
        return EL2GO_STATUS_INVALID_PARAMETER;

    mbedtls_x509_crt_init(&cert);

    /* mbedtls_x509_crt_parse accepts both PEM (detects "-----BEGIN") and DER */
    ret = mbedtls_x509_crt_parse(&cert, cert_der, cert_der_len);
    if (ret != 0) {
        EL2GO_DBG_PRINTF(ERROR, "Certificate parse failed: -0x%04x\n", -ret);
        status = EL2GO_STATUS_NET_CRYPTO_INVALID_CERT;
        goto exit;
    }

    /* Extract EC public key in uncompressed format (0x04 || X || Y).
     * Uses the compat wrapper to handle API differences across mbedTLS versions:
     *   v2: ecp->grp / ecp->Q
     *   v3: ecp->private_grp / ecp->private_Q
     *   v4: mbedtls_pk_write_pubkey_der + ASN.1 parsing (mbedtls_pk_ec removed)
     */
    ret = mbedtls_compat_pk_get_ec_pubkey_raw(&cert.pk, pubkey_out, pubkey_out_size, pubkey_len);
    if (ret != 0) {
        EL2GO_DBG_PRINTF(ERROR, "EC public key export failed: -0x%04x\n", -ret);
        if (ret == MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL)
            status = EL2GO_STATUS_BUFFER_TOO_SMALL;
        else
            status = EL2GO_STATUS_NET_CRYPTO_INVALID_CERT;
        goto exit;
    }

    EL2GO_DBG_PRINTF(VERBOSE, "Public key extracted (%zu bytes)\n", *pubkey_len);

exit:
    mbedtls_x509_crt_free(&cert);

    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}

el2go_status_t net_crypto_cert_get_dn(const uint8_t *cert_der, size_t cert_der_len, bool is_subject,
                                      char *dn_out, size_t dn_out_size)
{
    int ret = 0;
    mbedtls_x509_crt cert = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;

    EL2GO_DBG_TRACE_FUNCTION_CALL;

    if (!cert_der || !cert_der_len || !dn_out || !dn_out_size)
        return EL2GO_STATUS_INVALID_PARAMETER;

    mbedtls_x509_crt_init(&cert);

    ret = mbedtls_x509_crt_parse(&cert, cert_der, cert_der_len);
    if (ret != 0) {
        EL2GO_DBG_PRINTF(ERROR, "Certificate parse failed: -0x%04x\n", -ret);
        status = EL2GO_STATUS_NET_CRYPTO_INVALID_CERT;
        goto exit;
    }

    ret = mbedtls_x509_dn_gets(dn_out, dn_out_size, is_subject ? &cert.subject : &cert.issuer);
    if (ret < 0) {
        EL2GO_DBG_PRINTF(ERROR, "DN extraction failed: -0x%04x\n", -ret);
        status = EL2GO_STATUS_NET_CRYPTO_INVALID_CERT;
        goto exit;
    }

    EL2GO_DBG_PRINTF(VERBOSE, "%s DN extracted: %s\n", is_subject ? "Subject" : "Issuer", dn_out);

exit:
    mbedtls_x509_crt_free(&cert);

    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}

el2go_status_t net_crypto_self_signed_cert(const char *subject, uint32_t key_id,
                                           const uint8_t *device_uuid, size_t device_uuid_len,
                                           uint8_t *cert_out, size_t *cert_out_len)
{
    int ret = 0;
    mbedtls_pk_context pk_key = { 0 };
    mbedtls_x509write_cert crt = { 0 };
    mbedtls_compat_rng_context *rng_ctx = NULL;
    char subject_name[256] = { 0 };
    const uint8_t serial_bytes[1] = { 1U };
    const char *pers = "el2go_self_signed_cert";
    mbedtls_md_type_t md_alg = MBEDTLS_MD_SHA256;
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    char *pos = NULL;
    size_t i = 0;
    size_t buffer_size = 0;
    size_t current_len = 0;
    size_t remaining = 0;

    EL2GO_DBG_TRACE_FUNCTION_CALL;

    if (!subject || !cert_out || !cert_out_len)
        return EL2GO_STATUS_INVALID_PARAMETER;

    if (!device_uuid || device_uuid_len == 0)
        return EL2GO_STATUS_INVALID_PARAMETER;

    /* Save the input buffer size */
    buffer_size = *cert_out_len;

    if (buffer_size == 0)
        return EL2GO_STATUS_INVALID_PARAMETER;

    /* Initialize structures */
    mbedtls_x509write_crt_init(&crt);
    mbedtls_pk_init(&pk_key);

    /* Initialize RNG using compatibility layer */
    ret = mbedtls_compat_rng_init(&rng_ctx, (const unsigned char *)pers, strlen(pers));
    if (ret != 0) {
        EL2GO_DBG_PRINTF(ERROR, "Failed to init RNG: -0x%04x\n", -ret);
        status = EL2GO_STATUS_NET_CRYPTO_CONFIG_FAILED;
        goto exit;
    }

    /* Build subject name with device UUID as serial number */
    ret = osal_snprintf(subject_name, sizeof(subject_name), "%s,serialNumber=", subject);
    if (ret < 0 || ret >= (int)sizeof(subject_name)) {
        status = EL2GO_STATUS_INVALID_PARAMETER;
        goto exit;
    }

    /* Append device UUID as hex string */
    pos = subject_name + strlen(subject_name);
    for (i = 0; i < device_uuid_len; i++) {
        /* Calculate current position and remaining space safely */
        if (SET_OVERFLOW(pos - subject_name, current_len)) {
            EL2GO_DBG_PRINTF(ERROR, "Pointer difference overflow\n");
            status = EL2GO_STATUS_INVALID_PARAMETER;
            goto exit;
        }

        if (current_len >= sizeof(subject_name)) {
            status = EL2GO_STATUS_INVALID_PARAMETER;
            goto exit;
        }
        remaining = sizeof(subject_name) - current_len;

        /* Need 3 bytes: 2 hex digits + null terminator */
        if (remaining < 3) {
            status = EL2GO_STATUS_INVALID_PARAMETER;
            goto exit;
        }

        ret = osal_sprintf(pos, "%02X", device_uuid[i]);
        if (ret < 0) {
            status = EL2GO_STATUS_INCOMPLETE_DATA;
            goto exit;
        }
        pos += 2;
    }

    /* Setup opaque key reference using compatibility layer */
    EL2GO_DBG_PRINTF(DEBUG, "Setting opaque for key ID %x\n", key_id);
    ret = mbedtls_compat_pk_setup_key(&pk_key, key_id);
    if (ret != 0) {
        EL2GO_DBG_PRINTF(ERROR, "pk_setup_key failed: -0x%04x\n", -ret);
        status = EL2GO_STATUS_NET_CRYPTO_INVALID_KEY;
        goto exit;
    }

    /* Set subject and issuer keys (self-signed) */
    mbedtls_x509write_crt_set_subject_key(&crt, &pk_key);
    mbedtls_x509write_crt_set_issuer_key(&crt, &pk_key);

    /* Set subject and issuer names (same for self-signed) */
    ret = mbedtls_x509write_crt_set_subject_name(&crt, subject_name);
    if (ret != 0) {
        status = EL2GO_STATUS_NET_CRYPTO_CONFIG_FAILED;
        goto exit;
    }

    ret = mbedtls_x509write_crt_set_issuer_name(&crt, subject_name);
    if (ret != 0) {
        status = EL2GO_STATUS_NET_CRYPTO_CONFIG_FAILED;
        goto exit;
    }

    mbedtls_x509write_crt_set_version(&crt, MBEDTLS_X509_CRT_VERSION_3);

    /* Select hash algorithm based on key size */
    size_t key_bitlen = mbedtls_pk_get_bitlen(&pk_key);

    EL2GO_DBG_PRINTF(DEBUG, "Opaque key bit length: %zu\n", key_bitlen);

    if (key_bitlen == 384U)
        md_alg = MBEDTLS_MD_SHA384;

    EL2GO_DBG_PRINTF(DEBUG, "Using md_alg: 0x%x\n", (unsigned int)md_alg);
    mbedtls_x509write_crt_set_md_alg(&crt, md_alg);

    /* Set serial number using compatibility layer */
    ret = mbedtls_compat_x509write_crt_set_serial(&crt, serial_bytes, sizeof(serial_bytes));
    if (ret != 0) {
        status = EL2GO_STATUS_NET_CRYPTO_CONFIG_FAILED;
        goto exit;
    }

    /* Set validity period - fixed to avoid time sync issues */
    ret = mbedtls_x509write_crt_set_validity(&crt, "20220101000000", "99991231235959");
    if (ret != 0) {
        status = EL2GO_STATUS_NET_CRYPTO_CONFIG_FAILED;
        goto exit;
    }

    /* Set key usage extension (required to avoid zero-length extension) */
    ret = mbedtls_x509write_crt_set_key_usage(&crt, MBEDTLS_X509_KU_DIGITAL_SIGNATURE);
    if (ret != 0) {
        status = EL2GO_STATUS_NET_CRYPTO_CONFIG_FAILED;
        goto exit;
    }

    /* Write certificate in DER format using compatibility layer */
    /* Note: mbedtls_x509write_crt_der writes to the end of the buffer */
    ret = mbedtls_compat_x509write_crt_der(&crt, cert_out, buffer_size, rng_ctx);
    if (ret < 0) {
        EL2GO_DBG_PRINTF(ERROR, "Certificate generation failed: -0x%04x\n", -ret);
        if (ret == MBEDTLS_ERR_ASN1_BUF_TOO_SMALL) {
            EL2GO_DBG_PRINTF(ERROR, "Buffer too small (%zu bytes)\n", buffer_size);
            status = EL2GO_STATUS_BUFFER_TOO_SMALL;
        } else {
            status = EL2GO_STATUS_NET_CRYPTO_CONFIG_FAILED;
        }
        goto exit;
    }

    /* Move certificate to the beginning of the buffer */
    memmove(cert_out, cert_out + buffer_size - ret, ret);
    *cert_out_len = ret;

    EL2GO_DBG_PRINTF(INFO, "Self-signed certificate created (%zu bytes)\n", *cert_out_len);

exit:
    mbedtls_x509write_crt_free(&crt);
    mbedtls_pk_free(&pk_key);
    mbedtls_compat_rng_free(rng_ctx);

    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}
