/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

/*
 * mbedTLS debug helpers shared across the mbedTLS net_crypto backend.
 *
 * Provides:
 *   el2go_dbg_mbedtls_err()  - log high/low-level mbedTLS error strings
 *   mbedtls_debug_cb()       - mbedTLS internal trace callback
 */

#include <mbedtls/debug.h>
#ifdef MBEDTLS_ERROR_C
#include <mbedtls/error.h>
#endif

#include "compiler.h"
#include "debug.h"

#include "mbedtls_debug.h"

/**
 * @brief Log the human-readable mbedTLS error strings for a return code.
 *
 * Logs the high-level and low-level descriptions produced by mbedTLS when
 * MBEDTLS_ERROR_C is enabled. Does nothing when it is disabled.
 *
 * @param[in] ret  Negative mbedTLS error code.
 */
void el2go_dbg_mbedtls_err(int ret)
{
#ifdef MBEDTLS_ERROR_C
    char err_buf[256] = { 0 };

    mbedtls_strerror(ret, err_buf, sizeof(err_buf));
    EL2GO_DBG_PRINTF(ERROR, "mbedTLS error: %s\n", err_buf);
#else
    (void)ret;
#endif
}

/**
 * @brief Debug callback for the mbedTLS library.
 *
 * Pass this function to mbedtls_ssl_conf_dbg() to forward mbedTLS internal
 * trace messages unconditionally via EL2GO_PRINTF_ALWAYS, regardless of
 * ENABLE_TRACE or TRACE_LEVEL.
 *
 * @param[in] ctx    Context pointer (unused).
 * @param[in] level  mbedTLS debug level.
 * @param[in] file   Source file name reported by mbedTLS.
 * @param[in] line   Line number reported by mbedTLS.
 * @param[in] str    Debug message string.
 */
__maybe_unused void mbedtls_debug_cb(void *ctx, int level, const char *file, int line,
                                     const char *str)
{
    (void)ctx;
    (void)level;
    (void)file;
    (void)line;
    (void)str;

    EL2GO_PRINTF_ALWAYS("mbedTLS [%d] %s:%d: %s", level, file, line, str);
}
