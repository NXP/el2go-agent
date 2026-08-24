/*
 * Copyright 2023-2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __EL2GO_CLAIMCODE_ENCRYPT_H__
#define __EL2GO_CLAIMCODE_ENCRYPT_H__

#include <stddef.h>
#include <stdint.h>
#include "common/el2go_status.h"

/**
 * @brief Encrypt a plain claimcode string into a binary blob.
 *
 * Performs ECDH key agreement with the EL2GO server public key, derives
 * encryption and MAC keys, and produces a self-contained binary blob that
 * can be written to flash and later consumed by the RTP agent.
 *
 * @param[in]  claimcode             Null-terminated plain claimcode string.
 * @param[in]  el2go_public_key      EL2GO ECDH public key (64 bytes, uncompressed).
 * @param[in]  el2go_public_key_size Size of el2go_public_key in bytes.
 * @param[out] claimcode_blob        Caller-provided buffer to receive the blob.
 * @param[in,out] claimcode_blob_size On entry: size of the buffer.
 *                                    On exit: number of bytes written.
 *
 * @return EL2GO_STATUS_SUCCESS on success, EL2GO_STATUS_FAILURE on error.
 */
el2go_status_t el2go_claimcode_encrypt(const char *claimcode, const uint8_t *el2go_public_key,
                                       size_t el2go_public_key_size, uint8_t *claimcode_blob,
                                       size_t *claimcode_blob_size);

#endif /* __EL2GO_CLAIMCODE_ENCRYPT_H__ */
