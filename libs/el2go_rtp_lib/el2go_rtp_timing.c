/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "compiler.h"
#include "rtp/el2go_rtp_timing.h"
#include "el2go_rtp_internal.h"

__export el2go_status_t el2go_rtp_enable_timing(el2go_rtp_ctx_t *ctx)
{
    if (!ctx)
        return EL2GO_STATUS_INVALID_PARAMETER;

    ctx->timing_enabled = true;
    ctx->timing = (el2go_rtp_timing_t){ 0 };
    return EL2GO_STATUS_SUCCESS;
}

__export el2go_status_t el2go_rtp_disable_timing(el2go_rtp_ctx_t *ctx)
{
    if (!ctx)
        return EL2GO_STATUS_INVALID_PARAMETER;

    ctx->timing_enabled = false;
    return EL2GO_STATUS_SUCCESS;
}

__export el2go_status_t el2go_rtp_get_timing(el2go_rtp_ctx_t *ctx, el2go_rtp_timing_t *timing)
{
    if (!ctx || !timing)
        return EL2GO_STATUS_INVALID_PARAMETER;

    if (!ctx->timing_enabled)
        return EL2GO_STATUS_INVALID_STATE;

    *timing = ctx->timing;
    return EL2GO_STATUS_SUCCESS;
}
