/*
 * Copyright 2018-2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <stddef.h>

#include "compiler.h"
#include "osal.h"

#include "common/el2go_platform.h"
#include "platform_priv.h"
#include "plat_keys.h"

__export __weak el2go_status_t el2go_platform_init(el2go_platform_ctx_t **platform_ctx)
{
    if (!platform_ctx) {
        return EL2GO_STATUS_INVALID_PARAMETER;
    }

    /* platform specific code should provide implementation*/
    return EL2GO_STATUS_NOT_IMPLEMENTED;
}

__export __weak el2go_status_t el2go_platform_free(el2go_platform_ctx_t **platform_ctx)
{
    if (!platform_ctx || !*platform_ctx) {
        return EL2GO_STATUS_INVALID_PARAMETER;
    }

    *platform_ctx = NULL;

    /* platform specific code should provide implementation*/
    return EL2GO_STATUS_NOT_IMPLEMENTED;
}

__export __weak el2go_status_t el2go_platform_import_claimcode(el2go_platform_ctx_t *platform_ctx,
                                                               const char *claimcode)
{
    if (!platform_ctx || !claimcode) {
        return EL2GO_STATUS_INVALID_PARAMETER;
    }

    /* this function is not mandatory for all platforms*/
    return EL2GO_STATUS_SUCCESS;
}

__weak el2go_status_t el2go_platform_get_uuid(el2go_platform_ctx_t *platform_ctx, uint8_t **uuid,
                                              size_t *uuid_len)
{
    (void)platform_ctx;

    if (!uuid || !uuid_len) {
        return EL2GO_STATUS_INVALID_PARAMETER;
    }

    /* Default implementation delegates to OSAL layer.
	 * Platform-specific implementations can override this to retrieve
	 * UUID from hardware sources (HSM, OTP, eFuses, etc.)
	 */
    return osal_uuid(uuid, uuid_len);
}

__weak el2go_status_t el2go_platform_destroy_key(el2go_platform_ctx_t *platform_ctx,
                                                 const void *key_id)
{
    if (!platform_ctx || !key_id) {
        return EL2GO_STATUS_INVALID_PARAMETER;
    }

    /* this function is not mandatory for all platforms*/
    return EL2GO_STATUS_SUCCESS;
}

__weak el2go_status_t el2go_platform_get_el2go_key_id(el2go_platform_ctx_t *platform_ctx,
                                                      uint32_t *key_id)
{
    (void)platform_ctx;

    if (!platform_ctx || !key_id)
        return EL2GO_STATUS_INVALID_PARAMETER;

    *key_id = EDGELOCK2GO_KEYID_ECC;

    return EL2GO_STATUS_SUCCESS;
}

__weak el2go_status_t el2go_platform_get_el2go_cert(el2go_platform_ctx_t *platform_ctx,
                                                    uint8_t *cert, size_t *cert_len)
{
    (void)platform_ctx;
    (void)cert;
    (void)cert_len;

    /* Default implementation returns not available,
     * caller should fall back to self-signed certificate */
    return EL2GO_STATUS_CERT_NOT_AVAILABLE;
}
