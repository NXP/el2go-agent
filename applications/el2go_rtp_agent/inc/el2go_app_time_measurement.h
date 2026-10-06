/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file el2go_app_time_measurement.h
 * @brief Lightweight timing-measurement API for EL2GO RTP Agent demo.
 *
 * When EL2GO_TIME_MEASUREMENT_ENABLE is not defined (or == 0), all types
 * collapse to empty structs and all functions become no-ops -- call sites in
 * demo.c need no #ifdef guards at all.
 *
 * Enable via Kconfig : CONFIG_EL2GO_TIME_MEASUREMENT=y  (default y)
 * Enable via CMake   : -DEL2GO_TIME_MEASUREMENT_ENABLE=1
 */

#ifndef __EL2GO_APP_TIME_MEASUREMENT_H__
#define __EL2GO_APP_TIME_MEASUREMENT_H__

#include <stdint.h>

/* Kconfig bridge */
#if defined(CONFIG_EL2GO_TIME_MEASUREMENT)
#define EL2GO_TIME_MEASUREMENT_ENABLE 1
#endif

/* =========================================================================
 * ENABLED path
 * ========================================================================= */
#if defined(EL2GO_TIME_MEASUREMENT_ENABLE) && (EL2GO_TIME_MEASUREMENT_ENABLE == 1)

#include "el2go_app_sys.h"       /* el2go_app_sys_uptime_ms()  */
#include "el2go_rtp_agent_log.h" /* EL2GO_RTP_LOG_ALWAYS()     */

typedef struct {
    int64_t t_start_ms;
    int64_t t_end_ms;
} el2go_time_ctx_t;

typedef struct {
    long device_init_time;      /**< Network init (WiFi connect + DHCP) (ms)   */
    long init_time;             /**< Platform + agent + keystore + datastore (ms) */
    long claimcode_inject_time; /**< Claimcode import (ms)                     */
    long tls_prep_ms;           /**< TLS context preparation (ms)              */
    long network_connect_ms;    /**< TCP connect + TLS handshake (ms)          */
    long provision_time;        /**< el2go_rtp_provision() total duration (ms) */
    long crl_ms;                /**< CRL fetch + verification (ms)             */
    long command_txrx_ms;       /**< Protobuf dispatch loop (ms)               */
    long total_time;            /**< Entire agent_start() duration (ms)        */
} el2go_time_t;

static inline void el2go_time_init(el2go_time_ctx_t *ctx)
{
    ctx->t_start_ms = el2go_app_sys_uptime_ms();
    ctx->t_end_ms = ctx->t_start_ms;
}

static inline void el2go_time_conclude(el2go_time_ctx_t *ctx)
{
    ctx->t_end_ms = el2go_app_sys_uptime_ms();
}

static inline long el2go_time_get_ms(const el2go_time_ctx_t *ctx)
{
    int64_t delta = ctx->t_end_ms - ctx->t_start_ms;
    return (delta >= 0) ? (long)delta : 0L;
}

static inline void el2go_time_log_phase(const char *name, long ms)
{
    EL2GO_RTP_LOG_INFO("Performance timing: %s : %ldms", name, ms);
}

static inline void el2go_log_performance_timing(const el2go_time_t *t)
{
    EL2GO_RTP_LOG_ALWAYS("Performance timing: ENTIRE_SESSION_TIME : %ldms\r\n", t->total_time);
    EL2GO_RTP_LOG_ALWAYS("        Performance timing: AGENT_INIT_TIME : %ldms\r\n", t->init_time);
    EL2GO_RTP_LOG_ALWAYS("        Performance timing: TLS_PREP_TIME : %ldms\r\n", t->tls_prep_ms);
    EL2GO_RTP_LOG_ALWAYS("        Performance timing: NETWORK_CONNECT_TIME : %ldms\r\n",
                         t->network_connect_ms);
    EL2GO_RTP_LOG_ALWAYS("        Performance timing: PROCESS_PROVISION_TIME : %ldms\r\n",
                         t->provision_time);
    EL2GO_RTP_LOG_ALWAYS(
        "\tCRL_TIME : [%ldms] and COMMAND_TXRX_TIME : [%ldms] included in PROCESS_PROVISION_TIME\r\n",
        t->crl_ms, t->command_txrx_ms);
}

/* =========================================================================
 * DISABLED path -- all no-ops
 * ========================================================================= */
#else

typedef struct {
    char _dummy;
} el2go_time_ctx_t;
typedef struct {
    long device_init_time;
    long init_time;
    long claimcode_inject_time;
    long tls_prep_ms;
    long network_connect_ms;
    long provision_time;
    long crl_ms;
    long command_txrx_ms;
    long total_time;
} el2go_time_t;

static inline void el2go_time_init(el2go_time_ctx_t *ctx)
{
    (void)ctx;
}
static inline void el2go_time_conclude(el2go_time_ctx_t *ctx)
{
    (void)ctx;
}
static inline long el2go_time_get_ms(const el2go_time_ctx_t *ctx)
{
    (void)ctx;
    return 0L;
}
static inline void el2go_time_log_phase(const char *n, long ms)
{
    (void)n;
    (void)ms;
}
static inline void el2go_log_performance_timing(const el2go_time_t *t)
{
    (void)t;
}

#endif /* EL2GO_TIME_MEASUREMENT_ENABLE */

#endif /* __EL2GO_APP_TIME_MEASUREMENT_H__ */
