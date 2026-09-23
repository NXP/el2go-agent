/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <string.h>
#include <psa/crypto.h>
#include "net_crypto.h"

el2go_status_t net_crypto_sha256_stream(net_crypto_fetch_callback_t fetch_callback, void *context,
                                        uint8_t *hash_out)
{
    psa_hash_operation_t op = PSA_HASH_OPERATION_INIT;
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    uint8_t buffer[512] = { 0 };
    size_t bytes_read = 0;
    size_t hash_len = 0;

    if (fetch_callback == NULL || hash_out == NULL) {
        return EL2GO_STATUS_INVALID_PARAMETER;
    }

    status = psa_hash_setup(&op, PSA_ALG_SHA_256);
    if (status != PSA_SUCCESS) {
        return EL2GO_STATUS_FAILURE;
    }

    for (;;) {
        el2go_status_t fetch_status = EL2GO_STATUS_FAILURE;

        bytes_read = 0;
        fetch_status = fetch_callback(context, buffer, sizeof(buffer), &bytes_read);
        if (fetch_status != EL2GO_STATUS_SUCCESS) {
            (void)psa_hash_abort(&op);
            return EL2GO_STATUS_FAILURE;
        }
        if (bytes_read == 0U) {
            break;
        }

        status = psa_hash_update(&op, buffer, bytes_read);
        if (status != PSA_SUCCESS) {
            (void)psa_hash_abort(&op);
            return EL2GO_STATUS_FAILURE;
        }
    }

    status = psa_hash_finish(&op, hash_out, 32U, &hash_len);
    if (status != PSA_SUCCESS || hash_len != 32U) {
        return EL2GO_STATUS_FAILURE;
    }

    return EL2GO_STATUS_SUCCESS;
}

int net_crypto_ct_memcmp(const void *a, const void *b, size_t len)
{
    const uint8_t *pa = (const uint8_t *)a;
    const uint8_t *pb = (const uint8_t *)b;
    uint8_t diff = 0U;
    size_t i = 0U;

    if (a == NULL || b == NULL) {
        return -1;
    }

    for (i = 0U; i < len; i++) {
        diff |= (uint8_t)(pa[i] ^ pb[i]);
    }

    return (int)diff;
}
