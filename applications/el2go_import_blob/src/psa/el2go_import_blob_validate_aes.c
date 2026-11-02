/*
 * Copyright 2024-2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>
#include "el2go_import_blob.h"
#include "el2go_import_blob_validate.h"

void aes_enc_test(psa_key_type_t key_type, size_t key_id, const psa_algorithm_t key_alg)
{
    psa_status_t psa_status = PSA_SUCCESS;
    uint8_t *ciphertext = NULL;
    const uint8_t plaintext[] = "Encryption test";
    size_t ciphertext_size = PSA_CIPHER_ENCRYPT_OUTPUT_SIZE(key_type, key_alg, sizeof(plaintext));
    size_t ciphertext_length = 0U;

    ciphertext = malloc(ciphertext_size);
    if (ciphertext == NULL) {
        LOG("\r\n Cipher encrypt failed: out of memory! \r\n");
        return;
    }

    psa_status = psa_cipher_encrypt(key_id, key_alg, plaintext, sizeof(plaintext), ciphertext,
                                    ciphertext_size, &ciphertext_length);

    if (psa_status != PSA_SUCCESS) {
        LOG("\r\n Cipher encrypt failed! \r\n");
        goto cleanup;
    }

    LOG("\r\n Cipher encrypt passed! \r\n");

cleanup:
    free(ciphertext);
}
