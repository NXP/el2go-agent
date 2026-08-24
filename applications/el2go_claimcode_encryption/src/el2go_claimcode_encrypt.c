/*
 * Copyright 2023-2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "el2go_claimcode_encrypt.h"
#include "compiler.h"

/**
 * @brief Weak stub for el2go_claimcode_encrypt().
 *
 * This stub is overridden by a platform-specific backend (e.g. the ELS PKC
 * implementation in src/els_pkc/el2go_claimcode_encrypt_els.c) when the
 * corresponding backend Kconfig option is enabled.
 */
__weak el2go_status_t el2go_claimcode_encrypt(const char *claimcode,
                                              const uint8_t *el2go_public_key,
                                              size_t el2go_public_key_size, uint8_t *claimcode_blob,
                                              size_t *claimcode_blob_size)
{
    (void)claimcode;
    (void)el2go_public_key;
    (void)el2go_public_key_size;
    (void)claimcode_blob;
    (void)claimcode_blob_size;
    return EL2GO_STATUS_NOT_IMPLEMENTED;
}
