/*
 * Copyright 2024-2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>
#include "el2go_import_blob.h"
#include "el2go_import_blob_validate.h"

void ecc_sign_test(psa_key_type_t key_type, size_t key_id, const psa_algorithm_t key_alg)
{
    psa_status_t psa_status = PSA_SUCCESS;
    uint8_t *signature = NULL;
    const uint8_t message[] = "Sign message test";
    size_t signature_size = PSA_SIGN_OUTPUT_SIZE(key_type, 256, key_alg);
    size_t signature_length = 0U;

    signature = malloc(signature_size);
    if (signature == NULL) {
        LOG("\r\n Failed to allocate memory for signature \r\n");
        goto cleanup;
    }

    psa_status = psa_sign_message(key_id, key_alg, message, sizeof(message), signature,
                                  signature_size, &signature_length);

    if (psa_status != PSA_SUCCESS) {
        LOG("\r\n ECC sign failed! \r\n");
        goto cleanup;
    }

    LOG("\r\n ECC sign passed! \r\n");

cleanup:
    free(signature);
}
