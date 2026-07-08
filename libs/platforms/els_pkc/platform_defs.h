/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef __ELS_PKC_PLATFORM_DEFS_H__
#define __ELS_PKC_PLATFORM_DEFS_H__

/**
 * @brief ECC key ID for EdgeLock 2GO operations on ELS PKC platforms.
 *
 * References the client private key in the S50 secure enclave,
 * accessible via the ELS PKC PSA driver. The key never leaves
 * the secure enclave — signing is delegated to the S50 during
 * the TLS handshake.
 */
#define EDGELOCK2GO_KEYID_ECC 0x00003010U

#endif /* __ELS_PKC_PLATFORM_DEFS_H__ */