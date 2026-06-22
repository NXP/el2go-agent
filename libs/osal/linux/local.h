/*
 * Copyright 2021-2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef __LOCAL_H__
#define __LOCAL_H__

#include "osal.h"

/* Debug levels */
// clang-format off
#define OSAL_DBG_LEVEL_NONE    DBG_LEVEL_NONE
#define OSAL_DBG_LEVEL_ERROR   DBG_LEVEL_ERROR
#define OSAL_DBG_LEVEL_INFO    DBG_LEVEL_INFO
#define OSAL_DBG_LEVEL_DEBUG   DBG_LEVEL_DEBUG
#define OSAL_DBG_LEVEL_VERBOSE DBG_LEVEL_VERBOSE
#define OSAL_DBG_LEVEL_EXTRA   DBG_LEVEL_EXTRA
// clang-format on

#if defined(ENABLE_TRACE)

#define OSAL_DBG_PRINTF(level, ...)                                    \
	do {                                                           \
		osal_printf(OSAL_DBG_LEVEL_##level, "[   OSAL    ] "); \
		osal_printf(OSAL_DBG_LEVEL_##level, __VA_ARGS__);      \
	} while (0)

#define OSAL_DBG_PRINTF_COND(level, cond, ...)               \
	do {                                                 \
		if (cond)                                    \
			OSAL_DBG_PRINTF(level, __VA_ARGS__); \
	} while (0)

#define OSAL_TRACE_FUNCTION_CALL \
	OSAL_DBG_PRINTF(VERBOSE, "Executing %s\n", __func__)

#define OSAL_TRACE_EXTRA_FUNCTION_CALL \
	OSAL_DBG_PRINTF(EXTRA, "Executing %s\n", __func__)

#else
#define OSAL_DBG_PRINTF(level, ...)
#define OSAL_DBG_PRINTF_COND(...)
#define OSAL_TRACE_FUNCTION_CALL
#define OSAL_TRACE_EXTRA_FUNCTION_CALL
#endif /* ENABLE_TRACE */

/**
 * set_log_file() - Set log file from environment variable
 *
 * Reads EL2GO_LOG_FILE environment variable and redirects logging
 * output to that file. Defaults to stderr if the variable is not set or
 * the file cannot be opened.
 */
void set_log_file(void);

/**
 * set_log_level() - Set log level from environment variable
 *
 * Reads the EL2GO_LOG_LEVEL environment variable and configures
 * the logging verbosity level accordingly for filtering log messages.
 */
void set_log_level(void);

#endif /* __LOCAL_H__ */
