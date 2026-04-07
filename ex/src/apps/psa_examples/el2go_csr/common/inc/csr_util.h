/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef _CSR_UTIL_H_
#define _CSR_UTIL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "psa/crypto.h"
#include "mbedtls/x509_csr.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/pk.h"
#include "el2go_csr_osal_types.h"

// Default subject name components 
#ifndef CSR_SUBJECT_NAME
#define CSR_SUBJECT_CN          "FRDM-MCXE31B"
#define CSR_SUBJECT_O           "NXP"
#define CSR_SUBJECT_C           "GRATKORN"
#define CSR_SUBJECT_NAME        "CN=" CSR_SUBJECT_CN ",O=" CSR_SUBJECT_O ",C=" CSR_SUBJECT_C
#endif 

// Defintions for challenge-response mechanism to verify device authenticity
#define CHALLENGE_SIZE            (32u)
#define PSA_HASH_ALG              (PSA_ALG_SHA_256)
#define MBEDTLS_HASH_ALG          (MBEDTLS_MD_SHA256) // has to be same as PSA_HASH_ALG
#define PSA_SIG_ALG               (PSA_ALG_ECDSA(PSA_HASH_ALG))
#define MAX_HASH_SIZE             (32u)   
#define MAX_SIG_RAW_SIZE          (256u)  
#define MAX_ECDSA_DER_SIG_SIZE    (160u)  

/*! @brief Generate a Certificate Signing Request (CSR) using a PSA key.
 * 
 * @param[in]   key_id PSA key identifier to be used for CSR generation.
 * @param[out]  csr_output_buf Pointer to buffer where generated CSR will be stored.
 * @param[in]   csr_output_buf_size Size of the output buffer in bytes.
 * @param[out]  csr_output_len Pointer to variable where the length of generated CSR will be stored.
 * @retval PSA_SUCCESS: Certificate generation successful.
*/
psa_status_t 
generate_csr(psa_key_id_t key_id, uint8_t *csr_output_buf, size_t csr_output_buf_size, size_t *csr_output_len);

/*! @brief Verify provided x.509 certificate with PSA key. 
 *
 * @param[in]   key_id PSA key identifier to be used for verification.
 * @param[in]   cert_buf Pointer to buffer containing the x.509 certificate in PEM format.
 * @param[in]   cert_buf_size Size of the certificate buffer in bytes.
 * @retval PSA_SUCCESS: Certificate verification successful.
*/
psa_status_t
verify_certificate(psa_key_id_t key_id, const uint8_t *cert_buf, size_t cert_buf_size);

#ifdef __cplusplus
}
#endif

#endif /* _CSR_UTIL_H_ */
