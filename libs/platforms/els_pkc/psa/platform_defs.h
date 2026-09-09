/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef __ELS_PKC_PLATFORM_DEFS_H__
#define __ELS_PKC_PLATFORM_DEFS_H__

/** @defgroup els_pkc_psa_platform_defs ELS PKC PSA Platform Definitions
 * @brief Key and data object IDs for ELS PKC PSA platform builds.
 * @{
 */

/**
 * @brief ECC key ID for EdgeLock 2GO operations on ELS PKC platforms.
 *
 * References the client private key in the S50 secure enclave,
 * accessible via the ELS PKC PSA driver. The key never leaves
 * the secure enclave -- signing is delegated to the S50 during
 * the TLS handshake.
 */
#define EDGELOCK2GO_KEYID_ECC 0x3FFF0201U

/**
 * @brief Data object identifier for the EdgeLock 2GO claim code.
 *
 * Identifies the secure data object where the claim code is stored
 * via smw_store_data().
 */
#define EDGELOCK2GO_CLAIMCODE_DATA_ID 0x3F0000E0U

/** @} */ /* end of els_pkc_psa_platform_defs */

#endif /* __ELS_PKC_PLATFORM_DEFS_H__ */
