/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef __PLATFORM_PRIV_H__
#define __PLATFORM_PRIV_H__

#include <stdint.h>
#include <stddef.h>

#include "common/el2go_status.h"
#include "common/el2go_platform.h"

/**
 * @defgroup el2go_platform_int Platform Internal API
 * @brief Platform interface for internal module use.
 * @{
 */

/**
 * @brief Platform-specific fallback for destroying a key or object.
 *
 * This function provides a platform-specific mechanism to destroy keys or
 * objects when the standard keystore destroy API fails. Some platforms may
 * need alternative methods to handle certain types of secure objects.
 *
 * @param[in] platform_ctx  Platform context.
 * @param[in] key_id        Pointer to key or object identifier (platform-specific type).
 *
 * @return @ref el2go_status_t value, @ref EL2GO_STATUS_SUCCESS on success.
 */
el2go_status_t el2go_platform_destroy_key(el2go_platform_ctx_t *platform_ctx, const void *key_id);

/**
 * @brief Import claim code into platform-specific secure storage.
 *
 * Stores the claim code required for device provisioning. Platform-specific
 * implementations use hardware-backed storage (e.g. SMW encrypted store).
 * The default weak implementation returns EL2GO_STATUS_NOT_IMPLEMENTED,
 * signaling the keystore layer to use its own generic fallback.
 *
 * @param[in] platform_ctx  Platform context.
 * @param[in] claimcode     Null-terminated claim code string.
 *
 * @return @ref el2go_status_t value, @ref EL2GO_STATUS_SUCCESS on success,
 *         @ref EL2GO_STATUS_NOT_IMPLEMENTED if no platform override is present.
 */
el2go_status_t el2go_platform_import_claimcode(el2go_platform_ctx_t *platform_ctx,
                                               const char *claimcode, size_t claimcode_len);

/** @} */ /* end of el2go_platform_int */

#endif /* __PLATFORM_PRIV_H__ */
