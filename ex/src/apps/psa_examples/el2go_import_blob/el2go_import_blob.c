/*
 * Copyright 2024-2025 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "el2go_import_blob.h"

#if defined(SECURE_STORAGE)
#include "secure_storage.h"
#endif /* SECURE_STORAGE */

#if defined(VALIDATE_PSA_IMPORT_CERT) && VALIDATE_PSA_IMPORT_CERT
#include "mbedtls/x509.h"
#include "mbedtls/x509_crt.h"
#endif /* VALIDATE_PSA_IMPORT_CERT */

#ifndef __ZEPHYR__
#include "app.h"
#endif

#if defined(VALIDATE_PSA_IMPORT_MASTER_KEY) && VALIDATE_PSA_IMPORT_MASTER_KEY
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
#endif /* VALIDATE_PSA_IMPORT_MASTER_KEY */

#if defined(VALIDATE_PSA_IMPORT_KEY_PAIR) && VALIDATE_PSA_IMPORT_KEY_PAIR
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
#if defined(VALIDATE_PSA_IMPORT_CERT) && VALIDATE_PSA_IMPORT_CERT
static void export_cert(size_t certificate_id)
{
    uint8_t cert_buffer[2048] = {0U};
    mbedtls_x509_crt client_cert = {0};
#ifndef MBEDTLS_PK_ECP_PUB_DER_MAX_BYTES /*(mbedtls/library/pkwrite.h)*/
#define MBEDTLS_PK_ECP_PUB_DER_MAX_BYTES (30 + 2 * MBEDTLS_ECP_MAX_BYTES)
#endif
    uint8_t temp_buf[MBEDTLS_PK_ECP_PUB_DER_MAX_BYTES] = {0U};
    char outBuf[128] = {'\0'};
    psa_status_t psa_status = PSA_SUCCESS;

    size_t cert_len = 0U;
    psa_status = psa_export_key(certificate_id, // must match with key id of provisioned blob
                                cert_buffer,
                                sizeof(cert_buffer),
                                &cert_len);

    if (psa_status != PSA_SUCCESS) {
        LOG("\r\n Error in exporting the certificate! \r\n");
        goto cleanup;
    }

    LOG("Certificate in DER format: ");
    for (size_t i=0; i< cert_len; i++) 
    {
        LOG("%02X", *(cert_buffer + i));
    }
    LOG("\r\n");

    mbedtls_x509_crt_init(&client_cert);

    if (mbedtls_x509_crt_parse_der(&client_cert, cert_buffer, cert_len) != 0) 
    {
        LOG("\r\n Error in parsing the client certificate \r\n");
    }

    int len= mbedtls_x509_dn_gets(outBuf, sizeof(outBuf), &client_cert.subject);
    if (len < 0) {
        LOG("\r\n Error in getting the subject field from certificate \r\n");
    }
    LOG("Subject field in certificate is:%s\r\n", outBuf);

    len= mbedtls_x509_dn_gets(outBuf, sizeof(outBuf), &client_cert.issuer);
    if (len < 0) {
        LOG("\r\n Error in getting the issuer field from certificate \r\n");
    }
    LOG("Issuer field in certificate is:%s\r\n", outBuf);

    uint8_t *ptr = temp_buf + sizeof(temp_buf);
    len = mbedtls_pk_write_pubkey(&ptr, temp_buf, &client_cert.pk);
    if (len < 0) 
    {
        LOG(" \r\nError in extracting the public key from certificate \r\n");
    }
    
    LOG("Public_key: ");
    for (size_t i=0; i< len; i++) {
        LOG("%02X", *(ptr + i));
    }
    LOG("\r\n");

    mbedtls_x509_crt_free(&client_cert);
  
cleanup:
  // Future cleanup code goes here
  return;
}
#endif /* VALIDATE_PSA_IMPORT_CERT */
#endif /* VALIDATE_PSA_IMPORT_KEY_PAIR_AND_CERT */


int main(void)
{
  
#ifndef __ZEPHYR__
    BOARD_InitHardware();
#endif

    psa_status_t psa_status = PSA_SUCCESS;
      
#if defined(SECURE_STORAGE)
    /* Init secure storage */
    psa_status = secure_storage_its_initialize();
    if ( psa_status != PSA_SUCCESS)
    {
        LOG("\r\n secure_storage_its_initialize failed! \r\n");
        goto exit;
    }
#endif /* SECURE_STORAGE */

    psa_status = psa_crypto_init();
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
      
#if defined(VALIDATE_PSA_IMPORT_MASTER_KEY) && VALIDATE_PSA_IMPORT_MASTER_KEY 
    LOG("\r\nValidate imported blobs\r\n");
    
    /* validate the AES master key*/
    aes_enc_test(PSA_KEY_TYPE_AES, AES_KEY_ID, PSA_ALG_ECB_NO_PADDING);
#endif  /* VALIDATE_PSA_IMPORT_MASTER_KEY */
 
#if defined(VALIDATE_PSA_IMPORT_KEY_PAIR) && VALIDATE_PSA_IMPORT_KEY_PAIR
    /* validate the ecc key pair*/
    ecc_sign_test(PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1), ECC_KEY_PAIR_ID, PSA_ALG_ECDSA(PSA_ALG_SHA_256));

#if defined(VALIDATE_PSA_IMPORT_CERT) && VALIDATE_PSA_IMPORT_CERT
    /* validate the certificate*/
    export_cert(CERT_ID);
#endif  /* VALIDATE_PSA_IMPORT_CERT */
#endif  /* VALIDATE_PSA_IMPORT_KEY_PAIR */
    while(true);
    exit:
  	LOG("\r\n#### Import blob(s) from flash failed ####\r\n");
        while(true);
}