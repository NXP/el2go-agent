/*
 * Copyright 2024-2025 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "el2go_import_blob.h"

#ifndef __ZEPHYR__
#include "app.h"
#endif

#if defined(VALIDATE_PSA_IMPORT_OPERATION) && VALIDATE_PSA_IMPORT_OPERATION
void aes_enc_test(psa_key_type_t key_type, size_t key_id, const psa_algorithm_t key_alg)
{

    psa_status_t psa_status= PSA_SUCCESS;
    
    uint8_t *ciphertext = NULL;

    const uint8_t plaintext[] =  "Encryption test";
    size_t ciphertext_size = PSA_CIPHER_ENCRYPT_OUTPUT_SIZE(key_type, key_alg, sizeof(plaintext));
    
    ciphertext = malloc(ciphertext_size);
    size_t ciphertext_length = 0U;
    
    psa_status = psa_cipher_encrypt(key_id, 
                                    key_alg, 
                                    plaintext,
                                    sizeof(plaintext),
                                    ciphertext,
                                    ciphertext_size,
                                    &ciphertext_length);
    
    if (psa_status != PSA_SUCCESS) 
    {
        LOG("\r\n Cipher encrypt failed! \r\n");
        goto cleanup;
    }
    
    LOG("\r\n Cipher encrypt passed! \r\n");
    
cleanup:
    free(ciphertext);
}

void ecc_sign_test(psa_key_type_t key_type, size_t key_id, const psa_algorithm_t key_alg)
{
    psa_status_t psa_status = PSA_SUCCESS;
    uint8_t *signature = NULL;

    const uint8_t message[] =  "Sign message test";
    size_t signature_size = PSA_SIGN_OUTPUT_SIZE(key_type, 256, key_alg);
    signature = malloc(signature_size);
    size_t signature_length = 0U;
    
    psa_status = psa_sign_message(key_id, 
                                  key_alg, 
                                  message, 
                                  sizeof(message),
                                  signature,
                                  signature_size,
                                  &signature_length);
    
    if (psa_status != PSA_SUCCESS) 
    {
	LOG("\r\n ECC sign failed! \r\n");
	goto cleanup;
    }
    
    LOG("\r\n ECC sign passed! \r\n");

cleanup:
    free(signature);
}

#endif /* VALIDATE_PSA_IMPORT_OPERATION */

int main(void)
{
  
#ifndef __ZEPHYR__
    BOARD_InitHardware();
#endif
    
    psa_status_t psa_status = psa_crypto_init();
    if ( psa_status != PSA_SUCCESS)
    {
        LOG("\r\n psa_crypto_init failed! \r\n");
        goto exit;
    }
    
    size_t blobs_imported = 0U;
    psa_status_t psa_import_status = PSA_SUCCESS;
    
    psa_import_status = iot_agent_utils_psa_import_blobs_from_flash((uint8_t *)BLOB_AREA, BLOB_AREA_SIZE, &blobs_imported);
    if ( psa_import_status != PSA_SUCCESS)
    {
        goto exit;
    }

    LOG("\r\n%zx blob(s) imported from flash successfully\r\n", blobs_imported);
      
#if defined(VALIDATE_PSA_IMPORT_OPERATION) && VALIDATE_PSA_IMPORT_OPERATION 
    LOG("\r\nValidate imported blobs\r\n");
    
    aes_enc_test(PSA_KEY_TYPE_AES, AES_KEY_ID, PSA_ALG_ECB_NO_PADDING);
    
    ecc_sign_test(PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1), ECC_KEY_PAIR_ID, PSA_ALG_ECDSA(PSA_ALG_SHA_256));

#endif  /* VALIDATE_PSA_IMPORT_OPERATION */ 
    while(true);
    exit:
  	LOG("\r\n#### Import blob(s) from flash failed ####\r\n");
        while(true);
}