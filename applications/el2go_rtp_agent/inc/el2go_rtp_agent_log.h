/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __EL2GO_RTP_AGENT_LOG_H__
#define __EL2GO_RTP_AGENT_LOG_H__

#include "el2go_app_osal_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Debug level logging macro.
 * Includes function name and line number.
 */
#if defined(ENABLE_EL2GO_RTP_DEBUG) && ENABLE_EL2GO_RTP_DEBUG
#define EL2GO_RTP_LOG_DEBUG(...)                                   \
    do {                                                           \
        EL2GO_APP_PRINTC("DEBUG:   %s L#%d ", __func__, __LINE__); \
        EL2GO_APP_PRINTC(__VA_ARGS__);                             \
        EL2GO_APP_PRINTC("\r\n");                                  \
    } while (0)
#else
#define EL2GO_RTP_LOG_DEBUG(...)
#endif

/**
 * @brief Trace level logging macro.
 * Includes function name and line number.
 */
#if defined(ENABLE_EL2GO_RTP_TRACE) && ENABLE_EL2GO_RTP_TRACE
#define EL2GO_RTP_LOG_TRACE(...)                                   \
    do {                                                           \
        EL2GO_APP_PRINTC("TRACE:   %s L#%d ", __func__, __LINE__); \
        EL2GO_APP_PRINTC(__VA_ARGS__);                             \
        EL2GO_APP_PRINTC("\r\n");                                  \
    } while (0)
#define EL2GO_RTP_FUNC_ENTRY                                               \
    do {                                                                   \
        EL2GO_APP_PRINTC("FUNC_ENTRY:   %s L#%d\r\n", __func__, __LINE__); \
    } while (0)
#define EL2GO_RTP_FUNC_EXIT                                                \
    do {                                                                   \
        EL2GO_APP_PRINTC("FUNC_EXIT:    %s L#%d\r\n", __func__, __LINE__); \
    } while (0)
#define EL2GO_RTP_FUNC_EXIT_RC(x)                                                                \
    do {                                                                                         \
        EL2GO_APP_PRINTC("FUNC_EXIT:    %s L#%d return code : %d\r\n", __func__, __LINE__, (x)); \
        return (x);                                                                              \
    } while (0)
#else
#define EL2GO_RTP_LOG_TRACE(...)
#define EL2GO_RTP_FUNC_ENTRY
#define EL2GO_RTP_FUNC_EXIT
#define EL2GO_RTP_FUNC_EXIT_RC(x) \
    do {                          \
        return (x);               \
    } while (0)
#endif

/**
 * @brief Info level logging macro.
 * Message only -- no function name or line number.
 */
#if defined(ENABLE_EL2GO_RTP_INFO) && ENABLE_EL2GO_RTP_INFO
#define EL2GO_RTP_LOG_INFO(...)        \
    do {                               \
        EL2GO_APP_PRINTC(__VA_ARGS__); \
        EL2GO_APP_PRINTC("\r\n");      \
    } while (0)
#else
#define EL2GO_RTP_LOG_INFO(...)
#endif

/**
 * @brief Warning level logging macro.
 * Includes function name and line number.
 */
#if defined(ENABLE_EL2GO_RTP_WARN) && ENABLE_EL2GO_RTP_WARN
#define EL2GO_RTP_LOG_WARN(...)                                    \
    do {                                                           \
        EL2GO_APP_PRINTC("WARN:    %s L#%d ", __func__, __LINE__); \
        EL2GO_APP_PRINTC(__VA_ARGS__);                             \
        EL2GO_APP_PRINTC("\r\n");                                  \
    } while (0)
#else
#define EL2GO_RTP_LOG_WARN(...)
#endif

/**
 * @brief Error level logging macro.
 * Includes function name and line number.
 */
#if defined(ENABLE_EL2GO_RTP_ERROR) && ENABLE_EL2GO_RTP_ERROR
#define EL2GO_RTP_LOG_ERROR(...)                                   \
    do {                                                           \
        EL2GO_APP_PRINTC("ERROR:   %s L#%d ", __func__, __LINE__); \
        EL2GO_APP_PRINTC(__VA_ARGS__);                             \
        EL2GO_APP_PRINTC("\r\n");                                  \
    } while (0)
#define EL2GO_RTP_FUNC_EXIT_ERROR(x)                                                          \
    do {                                                                                      \
        EL2GO_APP_PRINTC("FUNC_EXIT_ERROR: %s L#%d return code : %d\r\n", __func__, __LINE__, \
                         (x));                                                                \
        return (x);                                                                           \
    } while (0)
#else
#define EL2GO_RTP_LOG_ERROR(...)
#define EL2GO_RTP_FUNC_EXIT_ERROR(x)
#endif

/**
 * @brief Always-on output -- used for banners and performance reports.
 * Not gated by any enable flag.
 */
#define EL2GO_RTP_LOG_ALWAYS(...)      \
    do {                               \
        EL2GO_APP_PRINTC(__VA_ARGS__); \
    } while (0)

#if defined(EL2GO_RTP_TEST) && EL2GO_RTP_TEST
#define EL2GO_RTP_TEST_LOG(ID, ...)               \
    do {                                          \
        EL2GO_APP_PRINTC("TEST_LOG(%s): ", (ID)); \
        EL2GO_APP_PRINTC(__VA_ARGS__);            \
        EL2GO_APP_PRINTC("\n");                   \
    } while (0)
#else
#define EL2GO_RTP_TEST_LOG(ID, ...)
#endif

#ifdef __cplusplus
}
#endif

#endif /* __EL2GO_RTP_AGENT_LOG_H__ */
