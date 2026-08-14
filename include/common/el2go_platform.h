/*
 * Copyright 2018-2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef __EL2GO_PLATFORM_H__
#define __EL2GO_PLATFORM_H__

#include <stddef.h>
#include <stdint.h>

#include "common/el2go_status.h"

/** Maximum number of bytes a device UUID can occupy. */
#define EL2GO_UUID_MAX_LEN 20U

/**
 * @defgroup el2go_platform_pub Platform Public API
 * @brief Public platform abstraction interface for EdgeLock 2GO.
 * @{
 */

/**
 * @brief Platform context.
 *
 * This is an opaque structure. Users should not access its members directly.
 * The actual definition is in the implementation files.
 */
typedef struct el2go_platform_ctx el2go_platform_ctx_t;

/**
 * @brief Initialize platform and HSM hardware.
 *
 * Initializes the platform-specific components including HSM hardware.
 * The SE05X underlying layers require parameters in the form of argc/argv.
 *
 * @param[out] platform_ctx  Pointer to store the created platform context.
 *
 * @return @ref el2go_status_t value, @ref EL2GO_STATUS_SUCCESS on success.
 */
el2go_status_t el2go_platform_init(el2go_platform_ctx_t **platform_ctx);

/**
 * @brief Cleanup platform and HSM hardware.
 *
 * Cleans up platform-specific resources and HSM hardware.
 *
 * @param[in,out] platform_ctx  Pointer to platform context (will be set to NULL).
 *
 * @return @ref el2go_status_t value, @ref EL2GO_STATUS_SUCCESS on success.
 */
el2go_status_t el2go_platform_free(el2go_platform_ctx_t **platform_ctx);

/**
 * @brief Retrieve the device UUID.
 *
 * Reads the platform-specific device unique identifier into a caller-provided
 * buffer. The UUID may originate from hardware sources (HSM, OTP, eFuses) or
 * fall back to the OSAL layer (e.g. Zephyr hwinfo).
 *
 * @param[in]  platform_ctx  Platform context (may be NULL on some platforms).
 * @param[out] buf           Caller-provided buffer to receive the raw UUID bytes.
 * @param[in]  buf_len       Size of the caller-provided buffer in bytes.
 * @param[out] uuid_len      Number of bytes written to buf on success.
 *
 * @return @ref el2go_status_t value, @ref EL2GO_STATUS_SUCCESS on success.
 * @return @ref EL2GO_STATUS_BUFFER_TOO_SMALL if @p buf_len is too small.
 * @return @ref EL2GO_STATUS_INVALID_PARAMETER if any pointer is NULL.
 */
el2go_status_t el2go_platform_get_uuid(el2go_platform_ctx_t *platform_ctx, uint8_t *buf,
                                       size_t buf_len, size_t *uuid_len);

/** @} */ /* end of el2go_platform_pub */

#endif /* __EL2GO_PLATFORM_H__ */
