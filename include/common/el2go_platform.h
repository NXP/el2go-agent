/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright 2018-2026 NXP
 */

#ifndef __EL2GO_PLATFORM_H__
#define __EL2GO_PLATFORM_H__

#include "common/el2go_status.h"

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

// clang-format off
/**
 * @brief Platform configuration.
 *
 * Platform-specific initialization parameters. The content and usage depend
 * on the underlying HSM implementation and its middleware requirements.
 *
 * @note Some HSM middleware layers require specific parameter formats that
 * cannot be modified. These fields accommodate those requirements while
 * remaining flexible for different platform implementations.
 */
typedef struct {
	int param_count;   /**< Number of platform parameters. */
	char **param_list; /**< Array of platform parameter strings. */
} el2go_platform_config_t;
// clang-format on

/**
 * @brief Initialize platform and HSM hardware.
 *
 * Initializes the platform-specific components including HSM hardware.
 * The SE05X underlying layers require parameters in the form of argc/argv.
 *
 * @param[in]  config        Platform configuration.
 * @param[out] platform_ctx  Pointer to store the created platform context.
 *
 * @return @ref el2go_status_t value, @ref EL2GO_STATUS_SUCCESS on success.
 */
el2go_status_t el2go_platform_init(const el2go_platform_config_t *config,
				   el2go_platform_ctx_t **platform_ctx);

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
 * @brief Import claim code for device provisioning.
 *
 * Imports the claim code required for device provisioning with EdgeLock 2GO.
 *
 * @param[in] platform_ctx  Platform context.
 * @param[in] claimcode     Claim code string.
 *
 * @return @ref el2go_status_t value, @ref EL2GO_STATUS_SUCCESS on success.
 */
el2go_status_t el2go_claimcode_import(el2go_platform_ctx_t *platform_ctx,
				      const char *claimcode);

/** @} */ /* end of el2go_platform_pub */

#endif /* __EL2GO_PLATFORM_H__ */
