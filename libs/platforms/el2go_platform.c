// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright 2018-2026 NXP
 */

#include <stddef.h>

#include "common/el2go_platform.h"
#include "compiler.h"

__export el2go_status_t
el2go_platform_init(const el2go_platform_config_t *config,
		    el2go_platform_ctx_t **platform_ctx)
{
	if (!config || !platform_ctx)
		return EL2GO_STATUS_FAILURE;

	/* TODO: Implement platform initialization */
	/* TODO: Initialize HSM hardware */

	return EL2GO_STATUS_SUCCESS;
}

__export el2go_status_t el2go_platform_free(el2go_platform_ctx_t **platform_ctx)
{
	if (!platform_ctx || !*platform_ctx)
		return EL2GO_STATUS_FAILURE;

	/* TODO: Cleanup HSM hardware */
	/* TODO: Free platform resources */

	*platform_ctx = NULL;

	return EL2GO_STATUS_SUCCESS;
}

__export el2go_status_t
/* force clang format */
el2go_claimcode_import(el2go_platform_ctx_t *platform_ctx,
		       const char *claimcode)
{
	if (!platform_ctx || !claimcode)
		return EL2GO_STATUS_FAILURE;

	/* TODO: Validate claim code format */
	/* TODO: Store claim code in platform-specific secure storage */

	return EL2GO_STATUS_SUCCESS;
}
