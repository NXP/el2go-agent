/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */
/** @file */
#ifndef _EL2GO_CSR_CSR_PSA_KEY_H_
#define _EL2GO_CSR_CSR_PSA_KEY_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "psa/crypto.h"

/*! @brief Fill PSA key attributes and (re)-generate key for CSR operation.
 * 
 * @param[in,out] attr: Pointer to PSA key attributes structure to be filled.   
 * @param[in] key_identifier: PSA key identifier to be used for the CSR operation.
 * @param[in] regenration_flag: Boolean flag indicating whether to regenerate an existing key.
 * @retval PSA_SUCCESS: PSA key attributes filled and key (re)-generated successfully.
*/
psa_status_t generate_key(psa_key_attributes_t *attr, psa_key_id_t* key_id, bool regeneration_flag);


#ifdef __cplusplus
}
#endif

#endif /* _EL2GO_CSR_CSR_PSA_KEY_H_ */
