/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef _EL2GO_CSR_CHALLENGE_H_
#define _EL2GO_CSR_CHALLENGE_H_

#include "psa/crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

/*! @brief Challenge-response configuration for certificate verification */
typedef struct {
    size_t challenge_size;          /* Size of the random challenge in bytes */
    psa_algorithm_t hash_alg;       /* PSA hash algorithm  */
    psa_algorithm_t sig_alg;        /* PSA signature algorithm  */
    psa_key_type_t key_type;        /* Sets the cryptographic algorithm type */
    size_t max_hash_size;           /* Maximum hash output size in bytes */
    size_t max_sig_raw_size;        /* Maximum raw signature size in bytes */
    size_t max_pub_key_size;        /* Max public key size in bytes */

} challenge_response_config_t;

/*! @brief Get the challenge-response configuration for this board.
 *
 * @return Pointer to the board-specific challenge-response configuration.
 */
const challenge_response_config_t* get_challenge_response_config(void);

#ifdef __cplusplus
}
#endif

#endif /* _EL2GO_CSR_CHALLENGE_H_ */
