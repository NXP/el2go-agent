/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

/*
 * TF-M stub for el2go_platform_register_el2go_key().
 *
 * When TF-M is used as the PSA backend, key management is handled entirely
 * by the TF-M secure partition. No explicit key registration is needed from
 * the non-secure side.
 */

#include "common/el2go_status.h"
#include "els_pkc_platform_priv.h"

el2go_status_t el2go_platform_register_el2go_key(void)
{
    /* TF-M manages the EL2GO connection key -- nothing to do here. */
    return EL2GO_STATUS_SUCCESS;
}
