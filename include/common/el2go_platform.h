/*
 * Copyright 2018-2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef __EL2GO_PLATFORM_H__
#define __EL2GO_PLATFORM_H__

#include "common/el2go_status.h"
#include <stddef.h>
#include <stdint.h>

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
 * @brief Recommended buffer size for el2go_platform_get_uuid().
 *
 * Allocate at least this many bytes when calling el2go_platform_get_uuid().
 * The actual UUID length is returned via the uuid_len output parameter.
 */
#define EL2GO_UUID_MAX_LEN 20U

/**
 * @brief Retrieve the device UUID.
 *
 * Writes the platform-specific device UUID into the caller-provided buffer.
 * The caller must supply a buffer of at least @ref EL2GO_UUID_MAX_LEN bytes.
 *
 * @param[in]  platform_ctx  Platform context.
 * @param[out] buf           Buffer to receive the UUID bytes.
 * @param[in]  buf_len       Size of @p buf in bytes.
 * @param[out] uuid_len      Set to the actual number of UUID bytes written.
 *
 * @retval @ref EL2GO_STATUS_SUCCESS on success.
 * @retval @ref EL2GO_STATUS_BUFFER_TOO_SMALL if @p buf_len is too small.
 * @retval @ref EL2GO_STATUS_INVALID_PARAMETER if any pointer is NULL.
 */
el2go_status_t el2go_platform_get_uuid(el2go_platform_ctx_t *platform_ctx, uint8_t *buf,
                                       size_t buf_len, size_t *uuid_len);

/** @} */ /* end of el2go_platform_pub */

#endif /* __EL2GO_PLATFORM_H__ */