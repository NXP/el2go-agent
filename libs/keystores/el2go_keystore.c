/*
 * Copyright 2018-2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */
#include "common/el2go_keystore.h"
#include "compiler.h"

__export el2go_status_t el2go_keystore_init(uint32_t id, el2go_keystore_type_t type,
                                            el2go_platform_ctx_t *platform_ctx,
                                            el2go_keystore_t *keystore)
{
    (void)id;
    (void)type;
    (void)platform_ctx;
    (void)keystore;

    /* TODO: Implement keystore initialization */
    return EL2GO_STATUS_FAILURE;
}

__export el2go_status_t el2go_keystore_free(el2go_keystore_t *keystore)
{
    (void)keystore;

    /* TODO: Free keystore resources */
    return EL2GO_STATUS_FAILURE;
}

__export el2go_status_t el2go_keystore_open_session(el2go_keystore_t *keystore)
{
    (void)keystore;

    /* TODO: Open keystore session */
    return EL2GO_STATUS_FAILURE;
}

__export el2go_status_t el2go_keystore_close_session(el2go_keystore_t *keystore)
{
    (void)keystore;

    /* TODO: Close keystore session */
    return EL2GO_STATUS_FAILURE;
}
