/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */
/** @file */
#ifndef __EL2GO_CSR_PSA_KEY_H__
#define __EL2GO_CSR_PSA_KEY_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "psa/crypto.h"

/*! @brief Fill platform specific PSA key attributes .
 *
 * @param[in,out] attr: Pointer to PSA key attributes structure to be filled.
 * @param[in] key_id: Pointer to PSA key identifier to be used for the CSR operation.
 * @retval None.
*/
void fill_key_attributes(psa_key_attributes_t *attr, psa_key_id_t *key_id);

#ifdef __cplusplus
}
#endif

#endif /* __EL2GO_CSR_PSA_KEY_H__ */
