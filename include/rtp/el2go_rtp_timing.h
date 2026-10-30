/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __EL2GO_RTP_TIMING_H__
#define __EL2GO_RTP_TIMING_H__

#include <stdint.h>
#include "common/el2go_status.h"

/**
 * @file el2go_rtp_timing.h
 * @brief Opt-in timing measurement API for the EL2GO RTP library.
 *
 * Call el2go_rtp_enable_timing() before el2go_rtp_provision() to activate
 * sub-phase measurements. After el2go_rtp_provision() returns, call
 * el2go_rtp_get_timing() to retrieve the results. Call
 * el2go_rtp_disable_timing() to stop measuring.
 *
 * When timing is not enabled, all measurement code in the library is a no-op
 * and there is zero runtime overhead.
 *
 * All time values are in milliseconds. A field is 0 if the corresponding
 * phase did not execute (e.g. crl_ms is 0 when CRL verification is disabled).
 */

/** Forward declaration -- defined in el2go_rtp_internal.h */
struct el2go_rtp_ctx;
typedef struct el2go_rtp_ctx el2go_rtp_ctx_t;

/**
 * @brief Sub-phase timing results from el2go_rtp_provision().
 *
 * Each field is used both as a scratch start-timestamp (while the phase is
 * in progress) and as the final elapsed-milliseconds result (after
 * EL2GO_TIMING_STOP returns). Fields are 0 for phases that did not execute.
 */
typedef struct {
    int64_t tls_prep_ms;        /**< Steps 1-7: cert fetch, net_crypto configure,
                                 *   set_server_cert, set_cli_cert, associate_key,
                                 *   set_cipher_suites, set_curves (ms) */
    int64_t network_connect_ms; /**< Step 8: TCP connect + TLS handshake (ms) */
    int64_t crl_ms;             /**< CRL fetch + verification; 0 if CRL disabled (ms) */
} el2go_rtp_timing_t;

/**
 * @brief Enable internal timing measurements.
 *
 * Must be called before el2go_rtp_provision(). Resets all timing fields to 0.
 *
 * @param[in] ctx  RTP agent context.
 * @return EL2GO_STATUS_SUCCESS or EL2GO_STATUS_INVALID_PARAMETER.
 */
el2go_status_t el2go_rtp_enable_timing(el2go_rtp_ctx_t *ctx);

/**
 * @brief Disable internal timing measurements.
 *
 * @param[in] ctx  RTP agent context.
 * @return EL2GO_STATUS_SUCCESS or EL2GO_STATUS_INVALID_PARAMETER.
 */
el2go_status_t el2go_rtp_disable_timing(el2go_rtp_ctx_t *ctx);

/**
 * @brief Retrieve timing results after el2go_rtp_provision() completes.
 *
 * Returns EL2GO_STATUS_INVALID_STATE if timing was not enabled.
 *
 * @param[in]  ctx     RTP agent context.
 * @param[out] timing  Caller-allocated struct to receive the results.
 * @return EL2GO_STATUS_SUCCESS, EL2GO_STATUS_INVALID_PARAMETER, or
 *         EL2GO_STATUS_INVALID_STATE.
 */
el2go_status_t el2go_rtp_get_timing(el2go_rtp_ctx_t *ctx, el2go_rtp_timing_t *timing);

#endif /* __EL2GO_RTP_TIMING_H__ */
