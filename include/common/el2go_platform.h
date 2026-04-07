/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright 2018-2026 NXP
 */

#ifndef __EL2GO_PLATFORM_H__
#define __EL2GO_PLATFORM_H__

#include "common/el2go_status.h"

/*
 * IoT Agent platform context
 *
 * This is an opaque structure. Users should not access its members directly.
 * The actual definition is in the implementation files.
 */
typedef struct el2go_agent_platform_ctx el2go_agent_platform_ctx_t;

/**
 * Platform configuration
 *
 * Platform-specific initialization parameters. The content and usage depend
 * on the underlying HSM implementation and its middleware requirements.
 *
 * Note: Some HSM middleware layers require specific parameter formats that
 * cannot be modified. These fields accommodate those requirements while
 * remaining flexible for different platform implementations.
 */
typedef struct {
	int param_count; /* Number of platform parameters */
	char **param_list; /* Array of platform parameter strings */
} el2go_agent_platform_config_t;

/**
 * el2go_agent_platform_init - Initialize platform and HSM hardware
 * @ctx: IoT Agent context
 * @config: Platform configuration
 * @platform_ctx: Pointer to store the created platform context
 *
 * Initializes the platform-specific components including HSM hardware.
 * The SE05X underlying layers require parameters in the form of argc/argv.
 *
 * Return:
 * EL2GO_AGENT_SUCCESS on success, error code otherwise
 */
el2go_agent_t
el2go_agent_platform_init(const el2go_agent_platform_config_t *config,
			  el2go_agent_platform_ctx_t **platform_ctx);

/**
 * el2go_agent_platform_free - Cleanup platform and HSM hardware
 * @ctx: IoT Agent context
 * @platform_ctx: Pointer to platform context (will be set to NULL)
 *
 * Cleans up platform-specific resources and HSM hardware.
 *
 * Return:
 * EL2GO_AGENT_SUCCESS on success, error code otherwise
 */
el2go_agent_t
el2go_agent_platform_free(el2go_agent_platform_ctx_t **platform_ctx);

/**
 * el2go_agent_claimcode_import - Import claim code for device provisioning
 * @platform_ctx: Platform context
 * @claimcode: Claim code string
 *
 * Imports the claim code required for device provisioning with EdgeLock 2GO.
 *
 * Return:
 * EL2GO_AGENT_SUCCESS on success, error code otherwise
 */
el2go_agent_t
el2go_agent_claimcode_import(el2go_agent_platform_ctx_t *platform_ctx,
			     const char *claimcode);

#endif /* __EL2GO_PLATFORM_H__ */
