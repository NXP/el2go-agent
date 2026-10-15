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

/*
 * Validation feature flags.
 *
 * These flags control both the C code path AND which source files are
 * compiled (via CMake). Because of the CMake-level source file gating,
 * these flags CANNOT be enabled by changing the #define below to 1.
 * Doing so only affects the log output -- the validation source files
 * will not be compiled and the weak stubs will be linked instead.
 *
 * To enable validation use ONE of these methods:
 *   1. Kconfig:  CONFIG_VALIDATE_PSA_IMPORT_MASTER_KEY=y  in prj.conf
 *   2. CMake:    west build ... -- -DVALIDATE_PSA_IMPORT_MASTER_KEY=1
 *
 * The #ifndef guards below exist so that the CMake-injected value
 * (method 1 or 2) is not overridden by this header.
 */
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
