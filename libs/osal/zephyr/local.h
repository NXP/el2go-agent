/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef __LOCAL_H__
#define __LOCAL_H__

#include "osal.h"

/* Debug level aliases (mirror the linux OSAL local.h) */
#define OSAL_DBG_LEVEL_NONE DBG_LEVEL_NONE
#define OSAL_DBG_LEVEL_ERROR DBG_LEVEL_ERROR
#define OSAL_DBG_LEVEL_INFO DBG_LEVEL_INFO
#define OSAL_DBG_LEVEL_DEBUG DBG_LEVEL_DEBUG
#define OSAL_DBG_LEVEL_VERBOSE DBG_LEVEL_VERBOSE
#define OSAL_DBG_LEVEL_EXTRA DBG_LEVEL_EXTRA

#if defined(ENABLE_TRACE)

#define OSAL_DBG_PRINTF(level, ...)                            \
    do {                                                       \
        osal_printf(OSAL_DBG_LEVEL_##level, "[   OSAL    ] "); \
        osal_printf(OSAL_DBG_LEVEL_##level, __VA_ARGS__);      \
    } while (0)

#define OSAL_DBG_PRINTF_COND(level, cond, ...)   \
    do {                                         \
        if (cond)                                \
            OSAL_DBG_PRINTF(level, __VA_ARGS__); \
    } while (0)

#define OSAL_TRACE_FUNCTION_CALL OSAL_DBG_PRINTF(VERBOSE, "Executing %s\n", __func__)

#define OSAL_TRACE_EXTRA_FUNCTION_CALL OSAL_DBG_PRINTF(EXTRA, "Executing %s\n", __func__)

#else /* ENABLE_TRACE */

#define OSAL_DBG_PRINTF(level, ...)
#define OSAL_DBG_PRINTF_COND(...)
#define OSAL_TRACE_FUNCTION_CALL
#define OSAL_TRACE_EXTRA_FUNCTION_CALL

#endif /* ENABLE_TRACE */

#endif /* __LOCAL_H__ */
