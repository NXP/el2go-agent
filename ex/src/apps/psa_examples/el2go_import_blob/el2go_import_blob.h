/*
 * Copyright 2024 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef _EL2GO_IMPORT_BLOB_H_
#define _EL2GO_IMPORT_BLOB_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "el2go_psa_import.h"

#define VALIDATE_PSA_IMPORT_OPERATION 0
  
#if VALIDATE_PSA_IMPORT_OPERATION

#define AES_KEY_ID              0x00003000
#define ECC_KEY_PAIR_ID         0x00003001

#endif /* VALIDATE_PSA_IMPORT_OPERATION */
  
#ifdef __cplusplus
}
#endif

#endif /* __EL2GO_IMPORT_BLOB_H__ */