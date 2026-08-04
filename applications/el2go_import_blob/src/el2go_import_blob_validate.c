/*
 * Copyright 2024-2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "el2go_import_blob_validate.h"

__attribute__((weak)) void aes_enc_test(psa_key_type_t key_type, size_t key_id,
                                        const psa_algorithm_t key_alg)
{
    (void)key_type;
    (void)key_id;
    (void)key_alg;
}

__attribute__((weak)) void ecc_sign_test(psa_key_type_t key_type, size_t key_id,
                                         const psa_algorithm_t key_alg)
{
    (void)key_type;
    (void)key_id;
    (void)key_alg;
}

__attribute__((weak)) void export_cert(size_t certificate_id)
{
    (void)certificate_id;
}
