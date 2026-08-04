/*
 * Copyright 2024-2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "el2go_import_blob.h"
#include "el2go_import_blob_validate.h"

int main(void)
{
    psa_status_t psa_status = PSA_SUCCESS;

    psa_status = psa_crypto_init();
    if (psa_status != PSA_SUCCESS) {
        LOG("\r\n psa_crypto_init failed! \r\n");
        goto exit;
    }

    size_t blobs_imported = 0U;
    psa_status_t psa_import_status = PSA_SUCCESS;

    psa_import_status =
        el2go_psa_import_blobs_from_flash((uint8_t *)BLOB_AREA, BLOB_AREA_SIZE, &blobs_imported);

    if (psa_import_status != PSA_SUCCESS) {
        goto exit;
    }

    LOG("%zx blob(s) imported from flash successfully\r\n", blobs_imported);

#if VALIDATE_PSA_IMPORT_MASTER_KEY || VALIDATE_PSA_IMPORT_KEY_PAIR || VALIDATE_PSA_IMPORT_CERT
    LOG("\r\nValidate imported blobs\r\n");
#endif

    aes_enc_test(PSA_KEY_TYPE_AES, AES_KEY_ID, PSA_ALG_ECB_NO_PADDING);

    ecc_sign_test(PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1), ECC_KEY_PAIR_ID,
                  PSA_ALG_ECDSA(PSA_ALG_SHA_256));

    export_cert(CERT_ID);

    while (true) {
        /* Spin after successful import */
    }

exit:
    LOG("\r\n#### Import blob(s) from flash failed ####\r\n");
    while (true) {
        /* Spin on error */
    }
}
