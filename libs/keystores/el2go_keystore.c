/*
 * Copyright 2018-2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <stddef.h>

#include "compiler.h"

#include "common/el2go_keystore.h"

__export __weak el2go_status_t el2go_keystore_init(uint32_t id, el2go_platform_ctx_t *platform_ctx,
                                                   el2go_keystore_t *keystore)
{
    (void)id;
    (void)platform_ctx;

    if (!keystore) {
        return EL2GO_STATUS_INVALID_PARAMETER;
    }

    return EL2GO_STATUS_SUCCESS;
}

__export __weak el2go_status_t el2go_keystore_free(el2go_keystore_t *keystore)
{
    if (!keystore) {
        return EL2GO_STATUS_INVALID_PARAMETER;
    }

    keystore->platform_ctx = NULL;

    return EL2GO_STATUS_SUCCESS;
}

__export __weak el2go_status_t el2go_keystore_open_session(el2go_keystore_t *keystore)
{
    if (!keystore) {
        return EL2GO_STATUS_INVALID_PARAMETER;
    }

    return EL2GO_STATUS_SUCCESS;
}

__export __weak el2go_status_t el2go_keystore_close_session(el2go_keystore_t *keystore)
{
    if (!keystore) {
        return EL2GO_STATUS_INVALID_PARAMETER;
    }

    return EL2GO_STATUS_SUCCESS;
}

__weak el2go_status_t el2go_keystore_handle_request(el2go_keystore_t *keystore,
                                                    const void *message_type, void *istream,
                                                    void *ostream)
{
    if (!keystore || !istream || !ostream || !message_type) {
        return EL2GO_STATUS_INVALID_PARAMETER;
    }

    return EL2GO_STATUS_SUCCESS;
}
