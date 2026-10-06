/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __EL2GO_RTP_TIMING_PRIV_H__
#define __EL2GO_RTP_TIMING_PRIV_H__

/*
 * Internal timing measurement macros.
 *
 * These macros access el2go_rtp_ctx_t internal fields (timing_enabled,
 * timing.*) and call osal_uptime_ms(). They must not be included from
 * public headers.
 *
 * Prerequisites before including this header:
 *   - el2go_rtp_internal.h  (defines el2go_rtp_ctx_t with timing fields)
 *   - osal.h                (declares osal_uptime_ms())
 */

/**
 * @brief Start a named timing measurement.
 *
 * Stores the current uptime into ctx->timing.<name>_ms. After a matching
 * EL2GO_TIMING_STOP the same field is overwritten with the elapsed duration.
 *
 * @param ctx   Pointer to an el2go_rtp_ctx_t; NULL is silently ignored.
 * @param name  Token that identifies the phase. Must match the name of a
 *              field in el2go_rtp_timing_t and the same token passed to the
 *              corresponding EL2GO_TIMING_STOP call.
 */
#define EL2GO_TIMING_START(ctx, name)                         \
    do {                                                      \
        if ((ctx) != NULL && (ctx)->timing_enabled)           \
            (ctx)->timing.name##_ms = (long)osal_uptime_ms(); \
    } while (0)

/**
 * @brief Stop a named timing measurement and record the elapsed time.
 *
 * Computes elapsed = now - ctx->timing.<name>_ms and stores the result back
 * into the same field. Does nothing when timing is disabled or ctx is NULL.
 * Uses int64_t arithmetic to avoid overflow on 32-bit platforms.
 *
 * @param ctx   Pointer to an el2go_rtp_ctx_t; NULL is silently ignored.
 * @param name  Same token used in the corresponding EL2GO_TIMING_START call.
 */
#define EL2GO_TIMING_STOP(ctx, name)                                                               \
    do {                                                                                           \
        if ((ctx) != NULL && (ctx)->timing_enabled)                                                \
            (ctx)->timing.name##_ms = (long)(osal_uptime_ms() - (int64_t)(ctx)->timing.name##_ms); \
    } while (0)

#endif /* __EL2GO_RTP_TIMING_PRIV_H__ */
