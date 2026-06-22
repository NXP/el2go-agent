/*
 * Copyright 2020-2024, 2026 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef __DEBUG_H__
#define __DEBUG_H__

#include "osal.h"

/* Debug levels */
// clang-format off
#define EL2GO_DBG_LEVEL_NONE    DBG_LEVEL_NONE
#define EL2GO_DBG_LEVEL_ERROR   DBG_LEVEL_ERROR
#define EL2GO_DBG_LEVEL_INFO    DBG_LEVEL_INFO
#define EL2GO_DBG_LEVEL_DEBUG   DBG_LEVEL_DEBUG
#define EL2GO_DBG_LEVEL_VERBOSE DBG_LEVEL_VERBOSE
#define EL2GO_DBG_LEVEL_EXTRA   DBG_LEVEL_EXTRA
// clang-format on

#if defined(ENABLE_TRACE)

#define EL2GO_PRINTF(level, ...)                 \
	do {                                     \
		osal_printf(level, "[EL2GO] ");  \
		osal_printf(level, __VA_ARGS__); \
	} while (0)

#define EL2GO_DBG_TRACE_API_CALL                                        \
	do {                                                            \
		EL2GO_PRINTF(EL2GO_DBG_LEVEL_VERBOSE, "Executing %s\n", \
			     __func__);                                 \
	} while (0)

#define EL2GO_DBG_TRACE_FUNCTION_CALL                                 \
	do {                                                          \
		EL2GO_PRINTF(EL2GO_DBG_LEVEL_EXTRA, "Executing %s\n", \
			     __func__);                               \
	} while (0)

#define EL2GO_DBG_PRINTF(level, ...)                                \
	do {                                                        \
		EL2GO_PRINTF(EL2GO_DBG_LEVEL_##level, __VA_ARGS__); \
	} while (0)

#define EL2GO_DBG_PRINTF_COND(level, cond, ...)                             \
	do {                                                                \
		if (cond)                                                   \
			EL2GO_PRINTF(EL2GO_DBG_LEVEL_##level, __VA_ARGS__); \
	} while (0)

#define EL2GO_DBG_HEX_DUMP(level, addr, size)                       \
	do {                                                        \
		osal_hex_dump(EL2GO_DBG_LEVEL_##level, addr, size); \
	} while (0)

#else /* ENABLE_TRACE */

#define EL2GO_PRINTF(...)
#define EL2GO_DBG_TRACE_API_CALL
#define EL2GO_DBG_TRACE_FUNCTION_CALL
#define EL2GO_DBG_PRINTF(level, ...)
#define EL2GO_DBG_PRINTF_COND(level, cond, ...)
#define EL2GO_DBG_HEX_DUMP(level, addr, size)

#endif /* ENABLE_TRACE */

#define EL2GO_DBG_ASSERT(exp)                                         \
	do {                                                          \
		if ((exp))                                            \
			break;                                        \
		EL2GO_PRINTF(EL2GO_DBG_LEVEL_ERROR,                   \
			     "Assertion \"%s\" failed: file \"%s\","  \
			     "line %d\n",                             \
			     #exp, __FILE__, __LINE__);               \
		/* Exit in error properly flushing/closing streams */ \
		exit(EXIT_FAILURE);                                   \
	} while (0)

#endif /* __DEBUG_H__ */
