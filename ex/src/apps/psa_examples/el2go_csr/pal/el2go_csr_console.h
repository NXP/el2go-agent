/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */
/** @file */
#ifndef _EL2GO_CSR_CONSOLE_H_
#define _EL2GO_CSR_CONSOLE_H_

#ifdef __cplusplus
extern "C" {
#endif

typedef enum _csr_log_level 
{
    LOG_INFO    = 0U,
    LOG_ERROR   = 1U,
    LOG_WARNING = 2U,
    LOG_TRACE   = 3U,
    LOG_DEBUG   = 4U
} csr_log_level; 

/* ANSI color codes */
#define ANSI_COLOR_RESET   "\033[0m"
#define ANSI_COLOR_RED     "\033[31m"
#define ANSI_COLOR_GREEN   "\033[32m"
#define ANSI_COLOR_YELLOW  "\033[33m"
#define ANSI_COLOR_MAGENTA "\033[35m"
#define ANSI_COLOR_CYAN    "\033[36m"

/* Log level prefixes with colors */
#define LOG_PREFIX_INFO    ANSI_COLOR_GREEN   "[INFO] "
#define LOG_PREFIX_ERROR   ANSI_COLOR_RED     "[ERROR] "
#define LOG_PREFIX_WARNING ANSI_COLOR_YELLOW  "[WARNING] "
#define LOG_PREFIX_TRACE   ANSI_COLOR_MAGENTA "[TRACE] "
#define LOG_PREFIX_DEBUG   ANSI_COLOR_CYAN    "[DEBUG] "

#ifdef __ZEPHYR__
#include <stdio.h>
#define scanc(fmt_s, ...)  scanf(fmt_s, ##__VA_ARGS__)
#define printc(log_lvl, fmt_s, ...) \
    printf("%s" fmt_s ANSI_COLOR_RESET, \
        (log_lvl) == LOG_INFO    ? LOG_PREFIX_INFO    : \
        (log_lvl) == LOG_ERROR   ? LOG_PREFIX_ERROR   : \
        (log_lvl) == LOG_WARNING ? LOG_PREFIX_WARNING : \
        (log_lvl) == LOG_TRACE   ? LOG_PREFIX_TRACE   : \
        (log_lvl) == LOG_DEBUG   ? LOG_PREFIX_DEBUG   : "[UNKNOWN] ", \
        ##__VA_ARGS__)
#else
#include "fsl_debug_console.h"
#define scanc(fmt_s, ...)  SCANF(fmt_s, ##__VA_ARGS__)
#define printc(log_lvl, fmt_s, ...) \
    PRINTF("%s" fmt_s ANSI_COLOR_RESET, \
        (log_lvl) == LOG_INFO    ? LOG_PREFIX_INFO    : \
        (log_lvl) == LOG_ERROR   ? LOG_PREFIX_ERROR   : \
        (log_lvl) == LOG_WARNING ? LOG_PREFIX_WARNING : \
        (log_lvl) == LOG_TRACE   ? LOG_PREFIX_TRACE   : \
        (log_lvl) == LOG_DEBUG   ? LOG_PREFIX_DEBUG   : "[UNKNOWN] ", \
        ##__VA_ARGS__)
#endif

#ifdef __cplusplus
}
#endif

#endif /* _EL2GO_CSR_CONSOLE_H_ */
