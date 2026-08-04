/*
 * Copyright 2024-2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _EL2GO_IMPORT_BLOB_VALIDATE_H_
#define _EL2GO_IMPORT_BLOB_VALIDATE_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <psa/crypto.h>

void aes_enc_test(psa_key_type_t key_type, size_t key_id, const psa_algorithm_t key_alg);
void ecc_sign_test(psa_key_type_t key_type, size_t key_id, const psa_algorithm_t key_alg);
void export_cert(size_t certificate_id);

#ifdef __cplusplus
}
#endif

#endif /* _EL2GO_IMPORT_BLOB_VALIDATE_H_ */
