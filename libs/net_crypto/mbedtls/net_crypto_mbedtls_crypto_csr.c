/*
 * Copyright 2018-2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

/*
 * CSR generation function -- compiled only when PEM write support is available
 * (MBEDTLS_PEM_WRITE_C). This prevents linker errors in builds that include
 * X.509 CSR write support (MBEDTLS_X509_CSR_WRITE_C) but not PEM output,
 * such as el2go_ota_agent_core.
 */

#include <string.h>
#include <stdlib.h>

#include <mbedtls/x509_csr.h>
#include <mbedtls/pk.h>
#include <mbedtls/error.h>

#include "osal.h"
#include "debug.h"

#include "net_crypto.h"

#include "crypto/mbedtls_compat_crypto.h"
#include "csr/mbedtls_compat_csr.h"
#include "mapping/mbedtls_mapping_md.h"

el2go_status_t net_crypto_generate_csr(uint32_t key_id, const char *subject_name,
                                       net_crypto_md_alg_t md_alg, uint8_t encoding,
                                       uint8_t *csr_out, size_t csr_out_size, size_t *csr_out_len)
{
    int ret = 0;
    mbedtls_pk_context pk = { 0 };
    mbedtls_x509write_csr csr = { 0 };
    mbedtls_compat_rng_context *rng_ctx = NULL;
    const char *pers = "el2go_generate_csr";
    el2go_status_t status = EL2GO_STATUS_SUCCESS;

    EL2GO_DBG_TRACE_FUNCTION_CALL;

    if (!subject_name || !csr_out || !csr_out_size || !csr_out_len)
        return EL2GO_STATUS_INVALID_PARAMETER;

    mbedtls_pk_init(&pk);
    mbedtls_x509write_csr_init(&csr);

    ret = mbedtls_compat_rng_init(&rng_ctx, (const unsigned char *)pers, strlen(pers));
    if (ret != 0) {
        EL2GO_DBG_PRINTF(ERROR, "Failed to init RNG: -0x%04x\n", -ret);
        status = EL2GO_STATUS_NET_CRYPTO_CONFIG_FAILED;
        goto exit;
    }

    ret = mbedtls_compat_pk_setup_key(&pk, key_id);
    if (ret != 0) {
        EL2GO_DBG_PRINTF(ERROR, "pk_setup_key failed: -0x%04x\n", -ret);
        status = EL2GO_STATUS_NET_CRYPTO_INVALID_KEY;
        goto exit;
    }

    mbedtls_x509write_csr_set_key(&csr, &pk);
    mbedtls_compat_x509write_csr_set_md_alg(&csr, map_md_alg(md_alg));

    ret = mbedtls_x509write_csr_set_subject_name(&csr, subject_name);
    if (ret != 0) {
        EL2GO_DBG_PRINTF(ERROR, "Set CSR subject name failed: -0x%04x\n", -ret);
        status = EL2GO_STATUS_NET_CRYPTO_CONFIG_FAILED;
        goto exit;
    }

    if (encoding == NET_CRYPTO_CSR_ENCODING_DER) {
        size_t der_len = 0U;

        ret = mbedtls_compat_x509write_csr_der(&csr, csr_out, csr_out_size, &der_len, rng_ctx);
        if (ret != 0) {
            EL2GO_DBG_PRINTF(ERROR, "CSR DER write failed: -0x%04x\n", -ret);
            if (ret == MBEDTLS_ERR_ASN1_BUF_TOO_SMALL)
                status = EL2GO_STATUS_BUFFER_TOO_SMALL;
            else
                status = EL2GO_STATUS_NET_CRYPTO_CONFIG_FAILED;
            goto exit;
        }
        *csr_out_len = der_len;
    } else {
        ret = mbedtls_compat_x509write_csr_pem(&csr, csr_out, csr_out_size, rng_ctx);
        if (ret != 0) {
            EL2GO_DBG_PRINTF(ERROR, "CSR PEM write failed: -0x%04x\n", -ret);
            if (ret == MBEDTLS_ERR_ASN1_BUF_TOO_SMALL)
                status = EL2GO_STATUS_BUFFER_TOO_SMALL;
            else
                status = EL2GO_STATUS_NET_CRYPTO_CONFIG_FAILED;
            goto exit;
        }

        *csr_out_len = 0U;
        while (csr_out[*csr_out_len] != '\0') {
            (*csr_out_len)++;
        }
    }

    EL2GO_DBG_PRINTF(INFO, "CSR generated (%zu bytes)\n", *csr_out_len);

exit:
    mbedtls_x509write_csr_free(&csr);
    mbedtls_pk_free(&pk);
    mbedtls_compat_rng_free(rng_ctx);

    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}
