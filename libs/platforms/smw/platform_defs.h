/*
 * Copyright 2018-2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef __SMW_PLATFORM_DEFS_H__
#define __SMW_PLATFORM_DEFS_H__

/** @defgroup smw_platform_defs SMW Platform Definitions
 * @brief Key and data object IDs for SMW-based platform builds.
 * @{
 */

/**
 * @brief ECC key ID for EdgeLock 2GO operations.
 *
 * This key ID is used for ECC cryptographic operations
 * in the EdgeLock Secure Enclave via SMW.
 */
#define EDGELOCK2GO_KEYID_ECC 0x7FFF816CU

/**
 * @brief Data object identifier for the EdgeLock 2GO claim code.
 *
 * Identifies the secure data object where the claim code is stored
 * via smw_store_data().
 */
#define EDGELOCK2GO_CLAIMCODE_DATA_ID 0xF00000E0U

/**
 * @brief AES-256 key ID used to encrypt the EdgeLock 2GO claim code at rest.
 */
#define EDGELOCK2GO_CLAIMCODE_ENC_KEY_ID 0x7FFF8171U

/**
 * @brief AES-256 key ID used to authenticate (CMAC) the EdgeLock 2GO claim code.
 */
#define EDGELOCK2GO_CLAIMCODE_AUTH_KEY_ID 0x7FFF8172U

/** @} */ /* end of smw_platform_defs */

#endif /* __SMW_PLATFORM_DEFS_H__ */
