/*
 * Copyright 2018-2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __IOT_AGENT_H__
#define __IOT_AGENT_H__

#include <stdint.h>
#include <stdbool.h>
#include "iot_agent_status.h"

/*
 * IoT Agent context
 *
 * This is an opaque structure. Users should not access its members directly.
 * The actual definition is in the implementation files.
 */
typedef struct iot_agent_ctx iot_agent_ctx_t;

/*
 * IoT Agent platform context
 *
 * This is an opaque structure. Users should not access its members directly.
 * The actual definition is in the implementation files.
 */
typedef struct iot_agent_keystore_ctx iot_agent_keystore_ctx_t;

/*
 * Status report verbosity levels
 */
typedef enum {
	IOT_AGENT_STATUS_SILENT,   /* Do not print status report */
	IOT_AGENT_STATUS_ON_ERROR, /* Print status report only on error */
	IOT_AGENT_STATUS_ALWAYS    /* Always print status report */
} iot_agent_status_verbosity_t;

/**
 * iot_agent_get_version - Get IoT Agent version information
 * @major: Pointer to store major version number
 * @minor: Pointer to store minor version number
 *
 * Return:
 * IOT_AGENT_SUCCESS on success, IOT_AGENT_FAILURE otherwise
 */
iot_agent_t iot_agent_get_version(unsigned int *major, unsigned int *minor);

/**
 * iot_agent_init - Initialize and allocate IoT Agent context
 * @ctx: Pointer to store allocated context
 *
 * Return:
 * IOT_AGENT_SUCCESS on success, IOT_AGENT_FAILURE otherwise
 */
iot_agent_t iot_agent_init(iot_agent_ctx_t **ctx);

/**
 * iot_agent_cleanup - Cleanup and free IoT Agent context
 * @ctx: Pointer to context (will be set to NULL)
 *
 * Return:
 * IOT_AGENT_SUCCESS on success, IOT_AGENT_FAILURE otherwise
 */
iot_agent_t iot_agent_cleanup(iot_agent_ctx_t **ctx);

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
	int param_count;    /* Number of platform parameters */
	char **param_list;  /* Array of platform parameter strings */
} iot_agent_platform_config_t;

/**
 * iot_agent_platform_init - Initialize platform and HSM hardware
 * @ctx: IoT Agent context
 * @config: Platform configuration
 * @platform_ctx: Pointer to store the created platform context
 *
 * Initializes the platform-specific components including HSM hardware.
 * The platform context is stored within the agent context for later use.
 * The SE05X underlying layers require parameters in the form of argc/argv.
 *
 * Return:
 * IOT_AGENT_SUCCESS on success, error code otherwise
 */
iot_agent_t
iot_agent_platform_init(iot_agent_ctx_t *ctx,
			const iot_agent_platform_config_t *config,
			iot_agent_keystore_ctx_t **platform_ctx);

/**
 * iot_agent_platform_cleanup - Cleanup platform and HSM hardware
 * @ctx: IoT Agent context
 * @platform_ctx: Pointer to platform context (will be set to NULL)
 *
 * Cleans up platform-specific resources and HSM hardware.
 * The platform context is removed from the agent context.
 *
 * Return:
 * IOT_AGENT_SUCCESS on success, error code otherwise
 */
iot_agent_t
iot_agent_platform_cleanup(iot_agent_ctx_t *ctx,
			   iot_agent_keystore_ctx_t **platform_ctx);

/**
 * iot_agent_claimcode_import - Import claim code for device provisioning
 * @platform_ctx: Platform context
 * @claimcode: Claim code string
 *
 * Imports the claim code required for device provisioning with EdgeLock 2GO.
 *
 * Return:
 * IOT_AGENT_SUCCESS on success, error code otherwise
 */
iot_agent_t
iot_agent_claimcode_import(iot_agent_keystore_ctx_t *platform_ctx,
			   const char *claimcode);
/**
  * iot_agent_update_device_configuration - Provision keys and certificates from server
  * @ctx: IoT Agent context
  * @verbosity: Status report verbosity level
  *
  * Connects to the EdgeLock 2GO server and provisions device keys and certificates.
  *
  * The function can optionally print the provisioning report received from the server.
  * Note: The report data is not currently exposed to the caller as it uses internal
  * protobuf structures. The API can be modified to provide a simplified or abstracted report
  * structure to avoid exposing protobuf implementation details to users.
  *
  * Return:
  * IOT_AGENT_SUCCESS on success, error code otherwise
  */
iot_agent_t
iot_agent_update_device_configuration(iot_agent_ctx_t *ctx,
				      iot_agent_status_verbosity_t verbosity);


#endif /* __IOT_AGENT_H__ */