/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

/*
 * Weak default implementation of el2go_platform_register_el2go_key().
 *
 * This no-op is always compiled and satisfies the linker symbol for any
 * build that does not need explicit key registration (e.g. OTA samples,
 * TF-M builds, or el2go_rtp_agent with CONFIG_EL2GO_RTP_PLATFORM_KEY_REGISTRATION=n).
 *
 * The strong real implementation in psa/els_pkc_key_registration.c overrides
 * this weak symbol when CONFIG_EL2GO_RTP_PLATFORM_KEY_REGISTRATION is enabled.
 */

#include "compiler.h"

#include "common/el2go_status.h"
#include "els_pkc_platform_priv.h"

__weak el2go_status_t el2go_platform_register_el2go_key(void)
{
    return EL2GO_STATUS_SUCCESS;
}
