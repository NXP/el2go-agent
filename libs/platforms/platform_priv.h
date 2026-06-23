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
 * @brief Get device UUID from platform.
 *
 * Retrieves the platform-specific device UUID. The UUID may come from
 * hardware sources such as OTP, eFuses, secure element, or other
 * platform-specific mechanisms.
 *
 * The function allocates memory for the UUID buffer. The caller is
 * responsible for freeing this memory using osal_free().
 *
 * @param[in]  platform_ctx  Platform context.
 * @param[out] uuid          Pointer to pointer where allocated UUID buffer will be stored.
 * @param[out] uuid_len      Pointer to size_t where actual UUID length will be stored.
 *
 * @return @ref el2go_status_t value, @ref EL2GO_STATUS_SUCCESS on success.
 */
el2go_status_t el2go_platform_get_uuid(el2go_platform_ctx_t *platform_ctx, uint8_t **uuid,
                                       size_t *uuid_len);

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

/** @} */ /* end of el2go_platform_int */

#endif /* __PLATFORM_PRIV_H__ */
