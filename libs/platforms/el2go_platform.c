// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright 2018-2026 NXP
 */

#include <stddef.h>

#include "compiler.h"
#include "osal.h"

#include "common/el2go_platform.h"
#include "platform_priv.h"

__export __weak el2go_status_t
el2go_platform_init(const el2go_platform_config_t *config,
		    el2go_platform_ctx_t **platform_ctx)
{
	if (!config || !platform_ctx)
		return EL2GO_STATUS_INVALID_PARAMETER;

	/* platform specific code should provide implementation*/
	return EL2GO_STATUS_NOT_IMPLEMENTED;
}

__export __weak el2go_status_t
el2go_platform_free(el2go_platform_ctx_t **platform_ctx)
{
	if (!platform_ctx || !*platform_ctx)
		return EL2GO_STATUS_INVALID_PARAMETER;

	*platform_ctx = NULL;

	/* platform specific code should provide implementation*/
	return EL2GO_STATUS_NOT_IMPLEMENTED;
}

__export __weak el2go_status_t
/* force clang format */
el2go_claimcode_import(el2go_platform_ctx_t *platform_ctx,
		       const char *claimcode)
{
	if (!platform_ctx || !claimcode)
		return EL2GO_STATUS_INVALID_PARAMETER;

	/* this function is not mandatory for all platforms*/
	return EL2GO_STATUS_SUCCESS;
}

__export __weak el2go_status_t el2go_platform_get_uuid(
	el2go_platform_ctx_t *platform_ctx, uint8_t **uuid, size_t *uuid_len)
{
	(void)platform_ctx;

	if (!uuid || !uuid_len)
		return EL2GO_STATUS_INVALID_PARAMETER;

	/* Default implementation delegates to OSAL layer.
	 * Platform-specific implementations can override this to retrieve
	 * UUID from hardware sources (HSM, OTP, eFuses, etc.)
	 */
	return osal_uuid(uuid, uuid_len);
}
