/*
 * Copyright 2023 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "el2go_blob_test_psa.h"
#include "mcuxClPsaDriver_Oracle_Macros.h"

#include <stdlib.h>
#include <string.h>

#define TEST_FAIL_PSA(msg)                           \
    PRINTF_SET_COLOR(RED);                           \
    PRINTF("  %s returned %d\r\n", msg, psa_status); \
    result->status = TEST_FAILED;                    \
    result->function = __FUNCTION__;                 \
    result->line = __LINE__;

#define TEST_FAIL(msg)               \
    result->status = TEST_FAILED;    \
    result->message = msg;           \
    result->function = __FUNCTION__; \
    result->line = __LINE__;

#define TEST_SKIP(msg)             \
    result->status = TEST_SKIPPED; \
    result->message = msg;

#define CHECK_PLACEHOLDER_BLOB(...)    \
    if (blob_size == 1)                \
    {                                  \
        TEST_SKIP("Placeholder blob"); \
        return;                        \
    }

void psa_blob_cipher_test(
    psa_key_type_t key_type,
    size_t key_bits,
    const psa_algorithm_t key_alg,
    psa_key_location_t key_location,
    size_t key_id,
    const uint8_t *blob,
    size_t blob_size,
    struct test_result_t *result)
{
    CHECK_PLACEHOLDER_BLOB();

    psa_status_t psa_status;
    psa_status = psa_crypto_init();
    if (psa_status != PSA_SUCCESS) {
        TEST_FAIL_PSA("psa_crypto_init");
        return;
    }

    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attributes, key_alg);
    psa_set_key_type(&attributes, key_type);
    psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(PSA_KEY_PERSISTENCE_DEFAULT, key_location));
    psa_set_key_bits(&attributes, key_bits);
    psa_set_key_id(&attributes, key_id);

    psa_key_id_t id = 0U;
    psa_status = psa_import_key(&attributes, blob, blob_size, &id);
    if (psa_status != PSA_SUCCESS) {
        TEST_FAIL_PSA("psa_import_key");
        return;
    }

    uint8_t *ciphertext = NULL;
    uint8_t *decrypted_plaintext = NULL;

    const uint8_t plaintext[] =  "This is the plaintxt to encrypt";
    size_t ciphertext_size = PSA_CIPHER_ENCRYPT_OUTPUT_SIZE(key_type, key_alg, sizeof(plaintext));
    ciphertext = malloc(ciphertext_size);
    size_t ciphertext_length = 0;
    psa_status = psa_cipher_encrypt(
        id, key_alg,
        plaintext,
        sizeof(plaintext),
        ciphertext,
        ciphertext_size,
        &ciphertext_length
    );
    if (psa_status != PSA_SUCCESS) {
        TEST_FAIL_PSA("psa_cipher_encrypt");
        goto cleanup;
    }

    size_t decrypted_plaintext_size = PSA_CIPHER_DECRYPT_OUTPUT_SIZE(key_type, key_alg, ciphertext_length);
    decrypted_plaintext = malloc(decrypted_plaintext_size);
    size_t decrypted_plaintext_length = 0;
    psa_status = psa_cipher_decrypt(
        id, key_alg,
        ciphertext,
        ciphertext_length,
        decrypted_plaintext,
        decrypted_plaintext_size,
        &decrypted_plaintext_length
    );
    if (psa_status != PSA_SUCCESS) {
        TEST_FAIL_PSA("psa_cipher_decrypt");
        goto cleanup;
    }

    uint32_t comp_result = memcmp(plaintext, decrypted_plaintext, sizeof(plaintext));
    if (comp_result != 0) {
        TEST_FAIL("Decrypted data doesn't match with plaintext");
        goto cleanup;
    }

cleanup:
    free(ciphertext);
    free(decrypted_plaintext);

    psa_status = psa_destroy_key(id);
    if (psa_status != PSA_SUCCESS) {
      TEST_FAIL_PSA("psa_destroy_key");
    }
}

void psa_blob_aead_test(
    psa_key_type_t key_type,
    size_t key_bits,
    const psa_algorithm_t key_alg,
    psa_key_location_t key_location,
    size_t key_id,
    const uint8_t *blob,
    size_t blob_size,
    struct test_result_t *result)
{
    CHECK_PLACEHOLDER_BLOB();

    psa_status_t psa_status;
    psa_status = psa_crypto_init();
    if (psa_status != PSA_SUCCESS) {
        TEST_FAIL_PSA("psa_crypto_init");
        return;
    }

    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attributes, key_alg);
    psa_set_key_type(&attributes, key_type);
    psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(PSA_KEY_PERSISTENCE_DEFAULT, key_location));
    psa_set_key_bits(&attributes, key_bits);
    psa_set_key_id(&attributes, key_id);

    psa_key_id_t id = 0U;
    psa_status = psa_import_key(&attributes, blob, blob_size, &id);
    if (psa_status != PSA_SUCCESS) {
        TEST_FAIL_PSA("psa_import_key");
        return;
    }

    uint8_t *nonce = NULL;
    uint8_t *ciphertext = NULL;
    uint8_t *decrypted_plaintext = NULL;

    size_t nonce_length = PSA_AEAD_NONCE_LENGTH(key_type, key_alg);
    nonce = malloc(nonce_length);
    psa_status = psa_generate_random(nonce, nonce_length);
    if (psa_status != PSA_SUCCESS) {
        TEST_FAIL_PSA("psa_generate_random");
        goto cleanup;
    }

    const uint8_t plaintext[] =  "This is the plaintxt to encrypt";
    size_t ciphertext_size = PSA_AEAD_ENCRYPT_OUTPUT_SIZE(key_type, key_alg, sizeof(plaintext));
    ciphertext = malloc(ciphertext_size);
    size_t ciphertext_length = 0;
    psa_status = psa_aead_encrypt(
        id, key_alg,
        nonce,
        nonce_length,
        0, 0,
        plaintext,
        sizeof(plaintext),
        ciphertext,
        ciphertext_size,
        &ciphertext_length
    );
    if (psa_status != PSA_SUCCESS) {
        TEST_FAIL_PSA("psa_aead_encrypt");
        goto cleanup;
    }

    size_t decrypted_plaintext_size = PSA_AEAD_DECRYPT_OUTPUT_SIZE(key_type, key_alg, ciphertext_length);
    decrypted_plaintext = malloc(decrypted_plaintext_size);
    size_t decrypted_plaintext_length = 0;
    psa_status = psa_aead_decrypt(
        id, key_alg,
        nonce,
        nonce_length,
        0, 0,
        ciphertext,
        ciphertext_length,
        decrypted_plaintext,
        decrypted_plaintext_size,
        &decrypted_plaintext_length
    );
    if (psa_status != PSA_SUCCESS) {
        TEST_FAIL_PSA("psa_aead_decrypt");
        goto cleanup;
    }

    uint32_t comp_result = memcmp(plaintext, decrypted_plaintext, sizeof(plaintext));
    if (comp_result != 0) {
        TEST_FAIL("Decrypted data doesn't match with plaintext");
        goto cleanup;
    }

cleanup:
    free(nonce);
    free(ciphertext);
    free(decrypted_plaintext);

    psa_status = psa_destroy_key(id);
    if (psa_status != PSA_SUCCESS) {
      TEST_FAIL_PSA("psa_destroy_key");
    }
}

void psa_blob_mac_test(
    psa_key_type_t key_type,
    size_t key_bits,
    const psa_algorithm_t key_alg,
    psa_key_location_t key_location,
    size_t key_id,
    const uint8_t *blob,
    size_t blob_size,
    struct test_result_t *result)
{
    CHECK_PLACEHOLDER_BLOB();

    psa_status_t psa_status;
    psa_status = psa_crypto_init();
    if (psa_status != PSA_SUCCESS) {
        TEST_FAIL_PSA("psa_crypto_init");
        return;
    }

    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_VERIFY_MESSAGE);
    psa_set_key_algorithm(&attributes, key_alg);
    psa_set_key_type(&attributes, key_type);
    psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(PSA_KEY_PERSISTENCE_DEFAULT, key_location));
    psa_set_key_bits(&attributes, key_bits);
    psa_set_key_id(&attributes, key_id);

    psa_key_id_t id = 0U;
    psa_status = psa_import_key(&attributes, blob, blob_size, &id);
    if (psa_status != PSA_SUCCESS) {
        TEST_FAIL_PSA("psa_import_key");
        return;
    }

    if (key_type == PSA_KEY_TYPE_HMAC) {
        TEST_SKIP("Internal HMAC unsupported by ELS");
        return;
    }

    uint8_t *mac = NULL;

    const uint8_t message[] =  "This is the message to authenticate";
    size_t mac_size = PSA_MAC_LENGTH(key_type, key_bits, key_alg);
    mac = malloc(mac_size);
    size_t mac_length = 0;
    psa_status = psa_mac_compute(
        id, key_alg,
        message,
        sizeof(message),
        mac,
        mac_size,
        &mac_length
    );
    if (psa_status != PSA_SUCCESS) {
        TEST_FAIL_PSA("psa_mac_compute");
        goto cleanup;
    }

    psa_status = psa_mac_verify(
        id, key_alg,
        message,
        sizeof(message),
        mac,
        mac_length
    );
    if (psa_status != PSA_SUCCESS) {
        TEST_FAIL_PSA("psa_mac_verify");
        goto cleanup;
    }

cleanup:
    free(mac);

    psa_status = psa_destroy_key(id);
    if (psa_status != PSA_SUCCESS) {
      TEST_FAIL_PSA("psa_destroy_key");
    }
}

void psa_blob_sigmsg_test(
    psa_key_type_t key_type,
    size_t key_bits,
    const psa_algorithm_t key_alg,
    psa_key_location_t key_location,
    size_t key_id,
    const uint8_t *blob,
    size_t blob_size,
    struct test_result_t *result)
{
    CHECK_PLACEHOLDER_BLOB();

    psa_status_t psa_status;
    psa_status = psa_crypto_init();
    if (psa_status != PSA_SUCCESS) {
        TEST_FAIL_PSA("psa_crypto_init");
        return;
    }

    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_VERIFY_MESSAGE);
    psa_set_key_algorithm(&attributes, key_alg);
    psa_set_key_type(&attributes, key_type);
    psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(PSA_KEY_PERSISTENCE_DEFAULT, key_location));
    psa_set_key_bits(&attributes, key_bits);
    psa_set_key_id(&attributes, key_id);

    psa_key_id_t id = 0U;
    psa_status = psa_import_key(&attributes, blob, blob_size, &id);
    if (psa_status != PSA_SUCCESS) {
        TEST_FAIL_PSA("psa_import_key");
        return;
    }

    uint8_t *signature = NULL;

    if(key_type == PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_K1) && key_bits == 224) {
        TEST_FAIL("EC secp224k1 currently broken [CLNS-8651]");
        goto cleanup;
    }

    const uint8_t message[] =  "This is the message to sign";
    size_t signature_size = PSA_SIGN_OUTPUT_SIZE(key_type, key_bits, key_alg);
    signature = malloc(signature_size);
    size_t signature_length = 0;
    psa_status = psa_sign_message(
        id, key_alg,
		message,
		sizeof(message),
		signature,
		signature_size,
		&signature_length
    );
    if (psa_status != PSA_SUCCESS) {
        TEST_FAIL_PSA("psa_sign_message");
        goto cleanup;
    }

    if (key_location == PSA_KEY_LOCATION_S50_BLOB_STORAGE) {
        TEST_FAIL("Verify with internal keypairs currently broken [CLNS-8459]");
        goto cleanup;
    }

    if (key_bits > 256) {
        TEST_FAIL("Verify with EC keypairs > 256 bit currently broken [CLNS-8652]");
        goto cleanup;
    }

    psa_status = psa_verify_message(
        id, key_alg,
		message,
		sizeof(message),
		signature,
		signature_length
    );
    if (psa_status != PSA_SUCCESS) {
        TEST_FAIL_PSA("psa_verify_message");
        goto cleanup;
    }

cleanup:
    free(signature);

    psa_status = psa_destroy_key(id);
    if (psa_status != PSA_SUCCESS) {
      TEST_FAIL_PSA("psa_destroy_key");
    }
}

void psa_blob_sighash_test(
    psa_key_type_t key_type,
    size_t key_bits,
    const psa_algorithm_t key_alg,
    psa_key_location_t key_location,
    size_t key_id,
    const uint8_t *blob,
    size_t blob_size,
    struct test_result_t *result)
{
    CHECK_PLACEHOLDER_BLOB();

    psa_status_t psa_status;
    psa_status = psa_crypto_init();
    if (psa_status != PSA_SUCCESS) {
        TEST_FAIL_PSA("psa_crypto_init");
        return;
    }

    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&attributes, key_alg);
    psa_set_key_type(&attributes, key_type);
    psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(PSA_KEY_PERSISTENCE_DEFAULT, key_location));
    psa_set_key_bits(&attributes, key_bits);
    psa_set_key_id(&attributes, key_id);

    psa_key_id_t id = 0U;
    psa_status = psa_import_key(&attributes, blob, blob_size, &id);
    if (psa_status != PSA_SUCCESS) {
        TEST_FAIL_PSA("psa_import_key");
        return;
    }

    uint8_t *hash = NULL;
    uint8_t *signature = NULL;

    psa_algorithm_t hash_alg = PSA_ALG_GET_HASH(key_alg);
    size_t hash_length = (hash_alg != PSA_ALG_NONE) ? PSA_HASH_LENGTH(hash_alg) : PSA_BITS_TO_BYTES(key_bits);
    hash = malloc(hash_length);
    psa_status = psa_generate_random(hash, hash_length);
    if (psa_status != PSA_SUCCESS) {
        TEST_FAIL_PSA("psa_generate_random");
        goto cleanup;
    }

    if(key_type == PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_K1) && key_bits == 224) {
        TEST_FAIL("EC secp224k1 currently broken [CLNS-8651]");
        goto cleanup;
    }

    size_t signature_size = PSA_SIGN_OUTPUT_SIZE(key_type, key_bits, key_alg);
    signature = malloc(signature_size);
    size_t signature_length = 0;
    psa_status = psa_sign_hash(
        id, key_alg,
		hash,
		hash_length,
		signature,
		signature_size,
		&signature_length
    );
    if (psa_status != PSA_SUCCESS) {
        TEST_FAIL_PSA("psa_sign_hash");
        goto cleanup;
    }

    if (key_location == PSA_KEY_LOCATION_S50_BLOB_STORAGE) {
        TEST_FAIL("Verify with internal keypairs currently broken [CLNS-8459]");
        goto cleanup;
    }

    if (key_bits > 256) {
        TEST_FAIL("Verify with EC keypairs < 256 bit currently broken [CLNS-8652]");
        goto cleanup;
    }

    psa_status = psa_verify_hash(
        id, key_alg,
		hash,
		hash_length,
		signature,
		signature_length
    );
    if (psa_status != PSA_SUCCESS) {
        TEST_FAIL_PSA("psa_verify_hash");
        goto cleanup;
    }

cleanup:
    free(hash);
    free(signature);

    psa_status = psa_destroy_key(id);
    if (psa_status != PSA_SUCCESS) {
      TEST_FAIL_PSA("psa_destroy_key");
    }
}

void psa_blob_export_test(
    psa_key_type_t key_type,
    size_t key_bits,
    const psa_algorithm_t key_alg,
    psa_key_location_t key_location,
    size_t key_id,
    const uint8_t *blob,
    size_t blob_size,
    struct test_result_t *result)
{
    CHECK_PLACEHOLDER_BLOB();

    if (PSA_BITS_TO_BYTES(key_bits) > 256) {
        TEST_FAIL("Large binary blobs currently broken [IOTDL-1381]");
        return;
    }

    psa_status_t psa_status;
    psa_status = psa_crypto_init();
    if (psa_status != PSA_SUCCESS) {
        TEST_FAIL_PSA("psa_crypto_init");
        return;
    }

    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attributes, key_alg);
    psa_set_key_type(&attributes, key_type);
    psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(PSA_KEY_PERSISTENCE_DEFAULT, key_location));
    psa_set_key_bits(&attributes, key_bits);
    psa_set_key_id(&attributes, key_id);

    psa_key_id_t id = 0U;
    psa_status = psa_import_key(&attributes, blob, blob_size, &id);
    if (psa_status != PSA_SUCCESS) {
        TEST_FAIL_PSA("psa_import_key");
        return;
    }

    uint8_t *exported_key = NULL;

    if (attributes.usage == PSA_KEY_USAGE_EXPORT) {
        TEST_FAIL("Export buffer size currently broken [CLNS-8532]");
        goto cleanup;
    }

    size_t exported_key_size = PSA_EXPORT_KEY_OUTPUT_SIZE(key_type, key_bits);
    exported_key = malloc(exported_key_size);
    size_t exported_key_length = 0;
	psa_status = psa_export_key(id, exported_key, exported_key_size, &exported_key_length);
    if (psa_status != PSA_SUCCESS) {
        TEST_FAIL_PSA("psa_export_key");
        goto cleanup;
    }

    if (exported_key_size != exported_key_length) {
        TEST_FAIL("Exported key has wrong size");
        goto cleanup;
    }

cleanup:
    free(exported_key);

    psa_status = psa_destroy_key(id);
    if (psa_status != PSA_SUCCESS) {
      TEST_FAIL_PSA("psa_destroy_key");
    }
}

void psa_blob_kdf_test(
    psa_key_type_t key_type,
    size_t key_bits,
    const psa_algorithm_t key_alg,
    psa_key_location_t key_location,
    size_t key_id,
    const uint8_t *blob,
    size_t blob_size,
    struct test_result_t *result)
{
    CHECK_PLACEHOLDER_BLOB();

    psa_status_t psa_status;
    psa_status = psa_crypto_init();
    if (psa_status != PSA_SUCCESS) {
        TEST_FAIL_PSA("psa_crypto_init");
        return;
    }

    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attributes, key_alg);
    psa_set_key_type(&attributes, key_type);
    psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(PSA_KEY_PERSISTENCE_DEFAULT, key_location));
    psa_set_key_bits(&attributes, key_bits);
    psa_set_key_id(&attributes, key_id);

    psa_key_id_t id = 0U;
    psa_status = psa_import_key(&attributes, blob, blob_size, &id);
    if (psa_status != PSA_SUCCESS) {
        TEST_FAIL_PSA("psa_import_key");
        return;
    }

    if (key_location == PSA_KEY_LOCATION_S50_BLOB_STORAGE) {
        TEST_SKIP("Internal HKDF unsupported by ELS");
        return;
    }

    psa_key_derivation_operation_t operation;
    operation = psa_key_derivation_operation_init();

    psa_status = psa_key_derivation_setup(&operation, key_alg);
    if (psa_status != PSA_SUCCESS) {
        TEST_FAIL_PSA("psa_key_derivation_setup");
        goto cleanup;
    }

    psa_status = psa_key_derivation_input_key(&operation, PSA_KEY_DERIVATION_INPUT_SECRET, id);
    if (psa_status != PSA_SUCCESS) {
        TEST_FAIL_PSA("psa_key_derivation_input_key");
        goto abort;
    }

    const uint8_t info[] = "This is my info";
    psa_status = psa_key_derivation_input_bytes(&operation, PSA_KEY_DERIVATION_INPUT_INFO, info, sizeof(info));
    if (psa_status != PSA_SUCCESS) {
        TEST_FAIL_PSA("psa_key_derivation_input_bytes");
        goto abort;
    }

    uint8_t derived_secret[16];
    psa_status = psa_key_derivation_output_bytes(&operation, derived_secret, sizeof(derived_secret));
    if (psa_status != PSA_SUCCESS) {
        TEST_FAIL_PSA("psa_key_derivation_output_bytes");
        goto abort;
    }

abort:
    psa_status = psa_key_derivation_abort(&operation);
    if (psa_status != PSA_SUCCESS) {
        TEST_FAIL_PSA("psa_key_derivation_abort");
    }
cleanup:
    psa_status = psa_destroy_key(id);
    if (psa_status != PSA_SUCCESS) {
      TEST_FAIL_PSA("psa_destroy_key");
    }
}

void psa_blob_keyexch_test(
    psa_key_type_t key_type,
    size_t key_bits,
    const psa_algorithm_t key_alg,
    psa_key_location_t key_location,
    size_t key_id,
    const uint8_t *blob,
    size_t blob_size,
    struct test_result_t *result)
{
    CHECK_PLACEHOLDER_BLOB();

    psa_status_t psa_status;
    psa_status = psa_crypto_init();
    if (psa_status != PSA_SUCCESS) {
        TEST_FAIL_PSA("psa_crypto_init");
        return;
    }

    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attributes, key_alg);
    psa_set_key_type(&attributes, key_type);
    psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_FROM_PERSISTENCE_AND_LOCATION(PSA_KEY_PERSISTENCE_DEFAULT, key_location));
    psa_set_key_bits(&attributes, key_bits);
    psa_set_key_id(&attributes, key_id);

    psa_key_id_t id = 0U;
    psa_status = psa_import_key(&attributes, blob, blob_size, &id);
    if (psa_status != PSA_SUCCESS) {
        TEST_FAIL_PSA("psa_import_key");
        return;
    }

    uint8_t *peer_key = NULL;
    uint8_t *output = NULL;

    size_t peer_key_length = PSA_BITS_TO_BYTES(key_bits);
    peer_key = malloc(peer_key_length);
    psa_status = psa_generate_random(peer_key, peer_key_length);
    if (psa_status != PSA_SUCCESS) {
        TEST_FAIL_PSA("psa_generate_random");
        goto cleanup;
    }

    if(key_alg == PSA_ALG_ECDH) {
        TEST_FAIL("ELS implementation currently broken [MCUX-59060]");
        goto cleanup;
    }

    size_t output_size = PSA_RAW_KEY_AGREEMENT_OUTPUT_SIZE(key_type, key_bits);
    output = malloc(output_size);
    size_t output_length = 0;
    psa_status = psa_raw_key_agreement(
        key_alg, id,
        peer_key,
        peer_key_length,
        output,
        output_size,
        &output_length
    );
    if (psa_status != PSA_SUCCESS) {
        TEST_FAIL_PSA("psa_raw_key_agreement");
        goto cleanup;
    }

    if (output_size != output_length) {
        TEST_FAIL("Shared secret has wrong size");
        goto cleanup;
    }

cleanup:
    free(peer_key);
    free(output);

    psa_status = psa_destroy_key(id);
    if (psa_status != PSA_SUCCESS) {
      TEST_FAIL_PSA("psa_destroy_key");
    }
}
