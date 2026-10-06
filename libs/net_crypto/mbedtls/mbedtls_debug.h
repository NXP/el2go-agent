/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef __MBEDTLS_DEBUG_H__
#define __MBEDTLS_DEBUG_H__

/**
 * @defgroup mbedtls_debug mbedTLS Debug Utilities
 * @brief Logging helpers for mbedTLS error codes and debug callbacks.
 * @{
 */

/* ========================================================================== */
/* Error string logging                                                        */
/* ========================================================================== */

/**
 * @brief Log the human-readable high-level and low-level mbedTLS error strings
 *        for a negative mbedTLS return code.
 *
 * Does nothing when MBEDTLS_ERROR_C is not enabled in the mbedTLS
 * configuration.
 *
 * @param ret  Negative mbedTLS error code (type int).
 */
void el2go_dbg_mbedtls_err(int ret);

/** Convenience macro so call sites read naturally. */
#define EL2GO_DBG_MBEDTLS_ERR(ret) el2go_dbg_mbedtls_err(ret)

/* ========================================================================== */
/* Debug callback                                                              */
/* ========================================================================== */

/**
 * @brief Debug callback for the mbedTLS library.
 *
 * Pass this function to mbedtls_ssl_conf_dbg() to forward mbedTLS internal
 * trace messages to EL2GO_DBG_PRINTF at VERBOSE level.
 *
 * @param[in] ctx    Context pointer (unused).
 * @param[in] level  mbedTLS debug level.
 * @param[in] file   Source file name reported by mbedTLS.
 * @param[in] line   Line number reported by mbedTLS.
 * @param[in] str    Debug message string.
 */
void mbedtls_debug_cb(void *ctx, int level, const char *file, int line, const char *str);

/** @} */

#endif /* __MBEDTLS_DEBUG_H__ */
