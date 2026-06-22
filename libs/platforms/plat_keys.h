/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef __PLAT_KEYS_H__
#define __PLAT_KEYS_H__

#include "platform_defs.h"

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

/** @} */ /* end of el2go_platform_int */

#endif /* __PLAT_KEYS_H__ */
