/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

/* Logging backend: Zephyr console.
 * Formats the line and writes it to the console via printk.
 * el2go_ota_diag_dump() and el2go_ota_diag_boot_replay() keep their weak
 * no-op defaults, lines are not stored. */

#include "el2go_app_compiler.h"
#include "el2go_ota_diag.h"

#include <stdarg.h>
#include <stdio.h>
#include <zephyr/sys/printk.h>

/* Lines longer than this are truncated. */
#define EL2GO_OTA_DIAG_LINE_MAX 160U

/**
 * @brief Formats a log line and writes it to the Zephyr console.
 *
 * Console backend implementation of el2go_ota_diag_emit(). Formats fmt with
 * the variadic arguments into a fixed stack buffer, truncating any output
 * that does not fit, then emits the result via printk.
 *
 * @param[in] level  Severity level (unused by this backend).
 * @param[in] fmt    printf-style format string.
 * @param[in] ...    Arguments for fmt.
 */
void el2go_ota_diag_emit(el2go_ota_diag_level_t level, const char *fmt, ...)
{
    char line[EL2GO_OTA_DIAG_LINE_MAX];
    va_list ap;
    int n;

    (void)level;

    va_start(ap, fmt);
    n = vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);

    if (n < 0) {
        return;
    }

    printk("%s", line);
}