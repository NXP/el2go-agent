/*
 * Copyright 2023 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef __EL2GO_BLOB_TEST_PSA_H__
#define __EL2GO_BLOB_TEST_PSA_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "el2go_blob_test.h"
#include "psa/crypto.h"

/**
 * \brief Run cipher tests with different blobs
 *
 * \param[in]  key_type     PSA key type
 * \param[in]  key_bits     Key size in bits
 * \param[in]  key_alg      PSA algorithm
 * \param[in]  key_location PSA location for the blob
 * \param[in]  key_id       Key ID
 * \param[in]  blob         Key blob from EL2GO
 * \param[in]  blob_size    Size of key blob from EL2GO
 * \param[out] result       Test result
 *
 */
void psa_blob_cipher_test(
    psa_key_type_t key_type,
    size_t key_bits,
    const psa_algorithm_t key_alg,
    psa_key_location_t key_location,
    size_t key_id,
    const uint8_t *blob,
    size_t blob_size,
    struct test_result_t *result
);

/**
 * \brief Run AEAD tests with different blobs
 *
 * \param[in]  key_type     PSA key type
 * \param[in]  key_bits     Key size in bits
 * \param[in]  key_alg      PSA algorithm
 * \param[in]  key_location PSA location for the blob
 * \param[in]  key_id       Key ID
 * \param[in]  blob         Key blob from EL2GO
 * \param[in]  blob_size    Size of key blob from EL2GO
 * \param[out] result       Test result
 *
 */
void psa_blob_aead_test(
    psa_key_type_t key_type,
    size_t key_bits,
    const psa_algorithm_t key_alg,
    psa_key_location_t key_location,
    size_t key_id,
    const uint8_t *blob,
    size_t blob_size,
    struct test_result_t *result
);

/**
 * \brief Run MAC tests with different blobs
 *
 * \param[in]  key_type     PSA key type
 * \param[in]  key_bits     Key size in bits
 * \param[in]  key_alg      PSA algorithm
 * \param[in]  key_location PSA location for the blob
 * \param[in]  key_id       Key ID
 * \param[in]  blob         Key blob from EL2GO
 * \param[in]  blob_size    Size of key blob from EL2GO
 * \param[out] result       Test result
 *
 */
void psa_blob_mac_test(
    psa_key_type_t key_type,
    size_t key_bits,
    const psa_algorithm_t key_alg,
    psa_key_location_t key_location,
    size_t key_id,
    const uint8_t *blob,
    size_t blob_size,
    struct test_result_t *result
);

/**
 * \brief Run Sign & Verify Message tests with different blobs
 *
 * \param[in]  key_type     PSA key type
 * \param[in]  key_bits     Key size in bits
 * \param[in]  key_alg      PSA algorithm
 * \param[in]  key_location PSA location for the blob
 * \param[in]  key_id       Key ID
 * \param[in]  blob         Key blob from EL2GO
 * \param[in]  blob_size    Size of key blob from EL2GO
 * \param[out] result       Test result
 *
 */
void psa_blob_sigmsg_test(
    psa_key_type_t key_type,
    size_t key_bits,
    const psa_algorithm_t key_alg,
    psa_key_location_t key_location,
    size_t key_id,
    const uint8_t *blob,
    size_t blob_size,
    struct test_result_t *result
);

/**
 * \brief Run Sign & Verify Hash tests with different blobs
 *
 * \param[in]  key_type     PSA key type
 * \param[in]  key_bits     Key size in bits
 * \param[in]  key_alg      PSA algorithm
 * \param[in]  key_location PSA location for the blob
 * \param[in]  key_id       Key ID
 * \param[in]  blob         Key blob from EL2GO
 * \param[in]  blob_size    Size of key blob from EL2GO
 * \param[out] result       Test result
 *
 */
void psa_blob_sighash_test(
    psa_key_type_t key_type,
    size_t key_bits,
    const psa_algorithm_t key_alg,
    psa_key_location_t key_location,
    size_t key_id,
    const uint8_t *blob,
    size_t blob_size,
    struct test_result_t *result
);

/**
 * \brief Run key export tests with different blobs
 *
 * \param[in]  key_type     PSA key type
 * \param[in]  key_bits     Key size in bits
 * \param[in]  key_alg      PSA algorithm
 * \param[in]  key_location PSA location for the blob
 * \param[in]  key_id       Key ID
 * \param[in]  blob         Key blob from EL2GO
 * \param[in]  blob_size    Size of key blob from EL2GO
 * \param[out] result       Test result
 *
 */
void psa_blob_export_test(
    psa_key_type_t key_type,
    size_t key_bits,
    const psa_algorithm_t key_alg,
    psa_key_location_t key_location,
    size_t key_id,
    const uint8_t *blob,
    size_t blob_size,
    struct test_result_t *result
);

/**
 * \brief Run KDF tests with different blobs
 *
 * \param[in]  key_type     PSA key type
 * \param[in]  key_bits     Key size in bits
 * \param[in]  key_alg      PSA algorithm
 * \param[in]  key_location PSA location for the blob
 * \param[in]  key_id       Key ID
 * \param[in]  blob         Key blob from EL2GO
 * \param[in]  blob_size    Size of key blob from EL2GO
 * \param[out] result       Test result
 *
 */
void psa_blob_kdf_test(
    psa_key_type_t key_type,
    size_t key_bits,
    const psa_algorithm_t key_alg,
    psa_key_location_t key_location,
    size_t key_id,
    const uint8_t *blob,
    size_t blob_size,
    struct test_result_t *result
);

/**
 * \brief Run key exchange tests with different blobs
 *
 * \param[in]  key_type     PSA key type
 * \param[in]  key_bits     Key size in bits
 * \param[in]  key_alg      PSA algorithm
 * \param[in]  key_location PSA location for the blob
 * \param[in]  key_id       Key ID
 * \param[in]  blob         Key blob from EL2GO
 * \param[in]  blob_size    Size of key blob from EL2GO
 * \param[out] result       Test result
 *
 */
void psa_blob_keyexch_test(
    psa_key_type_t key_type,
    size_t key_bits,
    const psa_algorithm_t key_alg,
    psa_key_location_t key_location,
    size_t key_id,
    const uint8_t *blob,
    size_t blob_size,
    struct test_result_t *result
);

#ifdef __cplusplus
}
#endif

#endif /* __EL2GO_BLOB_TEST_PSA_H__ */
