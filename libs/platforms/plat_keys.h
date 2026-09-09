/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef __PLAT_KEYS_H__
#define __PLAT_KEYS_H__

#include "platform_defs.h"
#include <stdint.h>
#include "common/el2go_status.h"
#include "common/el2go_platform.h"

/**
 * @addtogroup el2go_platform_int
 * @{
 */

/**
 * @brief ECC key ID used for EdgeLock 2GO client authentication.
 *
 * This key must be provisioned in the platform's secure keystore
 * before connecting to the EdgeLock 2GO server. It is used for:
 *  - Generating the self-signed client certificate
 *  - Mutual TLS authentication during the TLS handshake
 *
 * Defined per-platform in el2go_platform_defs.h.
 */
#ifndef EDGELOCK2GO_KEYID_ECC
#define EDGELOCK2GO_KEYID_ECC 0x7FFF816CU
#endif

/**
 * @brief Data object identifier for the EdgeLock 2GO claim code.
 *
 * Identifies the secure data object where the claim code is stored.
 * Defined per-platform in el2go_platform_defs.h.
 */
#ifndef EDGELOCK2GO_CLAIMCODE_DATA_ID
#define EDGELOCK2GO_CLAIMCODE_DATA_ID 0xF00000E0U
#endif

/**
 * @brief Get the ECC key ID for EdgeLock 2GO server connection
 *
 * Returns the ECC key ID used for client authentication with the
 * EdgeLock 2GO server. Platform-specific implementations can override
 * this to retrieve the key ID from hardware or configuration.
 *
 * @param[in] platform_ctx Platform context
 * @param[out] key_id Pointer to store the key ID
 *
 * @return EL2GO_STATUS_SUCCESS on success, error code otherwise
 */
el2go_status_t el2go_platform_get_el2go_key_id(el2go_platform_ctx_t *platform_ctx,
                                               uint32_t *key_id);

/**
 * @brief Get client certificate for EdgeLock 2GO connection
 *
 * @param[in] platform_ctx Platform context
 * @param[out] cert Pointer to buffer where certificate will be stored
 * @param[in,out] cert_len On input, size of buffer; on output, actual certificate length
 *
 * @retval EL2GO_STATUS_SUCCESS on success
 * @retval EL2GO_STATUS_CERT_NOT_AVAILABLE if no certificate is available
 * @retval error code otherwise
 */
el2go_status_t el2go_platform_get_el2go_cert(el2go_platform_ctx_t *platform_ctx, uint8_t *cert,
                                             size_t *cert_len);

/** @} */ /* end of el2go_platform_int */

#endif /* __PLAT_KEYS_H__ */
