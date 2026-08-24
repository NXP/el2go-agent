/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef __ELS_PKC_PLATFORM_DEFS_H__
#define __ELS_PKC_PLATFORM_DEFS_H__

/**
 * @brief ECC key ID for EdgeLock 2GO operations on TF-M builds.
 *
 * The key is managed by TF-M and exposed to the non-secure side via
 * the PSA Crypto API. The ID corresponds to the TF-M persistent key
 * slot assigned for the EL2GO connection authentication key.
 */
#define EDGELOCK2GO_KEYID_ECC 0x7FFF816CU

/**
 * @brief Data object identifier for the EdgeLock 2GO claim code (TF-M).
 *
 * Identifies the secure data object where the claim code is stored.
 */
#define EDGELOCK2GO_CLAIMCODE_DATA_ID 0xF00000E0U

#endif /* __ELS_PKC_PLATFORM_DEFS_H__ */
