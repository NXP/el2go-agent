/*
 * Copyright 2024-2026 NXP
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

#ifndef VALIDATE_PSA_IMPORT_MASTER_KEY
#define VALIDATE_PSA_IMPORT_MASTER_KEY 0
#endif

#define AES_KEY_ID 0x00003000

#ifndef VALIDATE_PSA_IMPORT_KEY_PAIR
#define VALIDATE_PSA_IMPORT_KEY_PAIR 0
#endif

#define ECC_KEY_PAIR_ID 0x00003001

#ifndef VALIDATE_PSA_IMPORT_CERT
#define VALIDATE_PSA_IMPORT_CERT 0
#endif

#define CERT_ID 0x00003002

#ifdef __cplusplus
}
#endif

#endif /* _EL2GO_IMPORT_BLOB_H_ */
