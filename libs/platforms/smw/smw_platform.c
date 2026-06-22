/*
 * Copyright 2018-2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <stddef.h>
#include <string.h>

#include <smw_osal.h>
#include <smw_device.h>
#include <psa/crypto.h>

#include "compiler.h"
#include "debug.h"
#include "osal.h"

#include "common/el2go_platform.h"
#include "platform_priv.h"


struct el2go_platform_ctx {
	bool smw_initialized;
};

__export el2go_status_t
el2go_platform_init(const el2go_platform_config_t *config,
		    el2go_platform_ctx_t **platform_ctx)
{
	el2go_platform_ctx_t *ctx = NULL;
	el2go_status_t status = EL2GO_STATUS_SUCCESS;
	psa_status_t psa_status = PSA_SUCCESS;

	EL2GO_DBG_TRACE_FUNCTION_CALL;

	/* the config parameter is not used for this type of platform */
	if (!config || !platform_ctx) {
		status = EL2GO_STATUS_INVALID_PARAMETER;
		goto exit;
	}

	/* Just return if platform already initialized */
	if (*platform_ctx && (*platform_ctx)->smw_initialized) {
		EL2GO_DBG_PRINTF(INFO, "Platform already initialized\n");
		return EL2GO_STATUS_SUCCESS;
	}

	/* Allocate platform context */
	ctx = osal_calloc(1, sizeof(el2go_platform_ctx_t));
	if (!ctx) {
		EL2GO_DBG_PRINTF(ERROR,
				 "Failed to allocate platform context\n");
		status = EL2GO_STATUS_ALLOCATION_ERROR;
		goto exit;
	}

	/* Initialize PSA crypto (depends on SMW) */
	psa_status = psa_crypto_init();
	if (psa_status != PSA_SUCCESS) {
		EL2GO_DBG_PRINTF(ERROR, "psa_crypto_init failed: %d\n",
				 (int)psa_status);
		status = EL2GO_STATUS_PLATFORM_INIT_FAILED;
		goto exit;
	}
	EL2GO_DBG_PRINTF(INFO, "PSA crypto initialized successfully\n");

	ctx->smw_initialized = true;
	*platform_ctx = ctx;

exit:
	if (status != EL2GO_STATUS_SUCCESS && ctx)
		osal_free(ctx);

	EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

__export el2go_status_t el2go_platform_free(el2go_platform_ctx_t **platform_ctx)
{
	el2go_status_t status = EL2GO_STATUS_SUCCESS;

	EL2GO_DBG_TRACE_FUNCTION_CALL;

	if (!platform_ctx || !*platform_ctx) {
		status = EL2GO_STATUS_INVALID_PARAMETER;
		goto exit;
	}

	/* Free platform context */
	osal_free(*platform_ctx);
	*platform_ctx = NULL;

exit:
	EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}

__export el2go_status_t /* force clang formatting */
el2go_platform_get_uuid(el2go_platform_ctx_t *platform_ctx, uint8_t **uuid,
			size_t *uuid_len)
{
	struct smw_device_uuid_args device_args = { 0 };
	enum smw_status_code smw_status = SMW_STATUS_OK;
	el2go_status_t status = EL2GO_STATUS_SUCCESS;
	uint8_t *uuid_buffer = NULL;

	EL2GO_DBG_TRACE_FUNCTION_CALL;

	if (!platform_ctx || !uuid || !uuid_len) {
		status = EL2GO_STATUS_INVALID_PARAMETER;
		goto exit;
	}

	if (!platform_ctx->smw_initialized) {
		EL2GO_DBG_PRINTF(ERROR, "Platform not initialized\n");
		status = EL2GO_STATUS_INVALID_PARAMETER;
		goto exit;
	}

	EL2GO_DBG_PRINTF(VERBOSE, "Getting device UUID from SMW\n");

	/* Setup SMW device UUID arguments for first call to get length */
	device_args.version = 0;
	device_args.subsystem_name = SMW_SUBSYSTEM_NAME_ELE;
	device_args.certificate_length = 0;
	device_args.certificate = NULL;
	device_args.uuid = NULL;
	device_args.uuid_length = 0;

	/* First call: Get required UUID length */
	smw_status = smw_device_get_uuid(&device_args);
	if (smw_status != SMW_STATUS_OK) {
		EL2GO_DBG_PRINTF(ERROR, "SMW UUID length failed: %d\n",
				 smw_status);
		status = EL2GO_STATUS_PLATFORM_SMW_ERROR;
		goto exit;
	}

	/* Allocate buffer for UUID */
	uuid_buffer = osal_malloc(device_args.uuid_length);
	if (!uuid_buffer) {
		EL2GO_DBG_PRINTF(ERROR, "Failed to allocate UUID buffer\n");
		status = EL2GO_STATUS_ALLOCATION_ERROR;
		goto exit;
	}

	/* Second call: Get actual UUID */
	device_args.uuid = uuid_buffer;

	smw_status = smw_device_get_uuid(&device_args);
	if (smw_status != SMW_STATUS_OK) {
		EL2GO_DBG_PRINTF(ERROR, "smw_device_get_uuid failed: %d\n",
				 smw_status);
		status = EL2GO_STATUS_PLATFORM_SMW_ERROR;
		goto exit;
	}

	/* Transfer ownership to caller */
	*uuid = uuid_buffer;
	*uuid_len = device_args.uuid_length;

	EL2GO_DBG_PRINTF(INFO,
			 "Device UUID retrieved successfully (%u bytes)\n",
			 device_args.uuid_length);
	EL2GO_DBG_HEX_DUMP(DEBUG, *uuid, *uuid_len);

exit:
	/* Free buffer only if ownership was not transferred */
	if (status != EL2GO_STATUS_SUCCESS && uuid_buffer)
		osal_free(uuid_buffer);

	EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
	return status;
}
