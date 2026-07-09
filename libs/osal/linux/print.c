/*
 * Copyright 2022-2024, 2026 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>

#include "osal.h"
#include "local.h"
#include "builtin_macros.h"

#define HEX_DUMP_LINE_LENGTH 16

static unsigned int log_level = TRACE_LEVEL;
static FILE *stddebug = NULL;

static FILE *get_debug_stream(void)
{
    if (!stddebug)
        return stderr;

    return stddebug;
}

void set_log_file(void)
{
    FILE *f = NULL;
    const char *file_name = getenv("EL2GO_LOG_FILE");

    stddebug = stderr;

    if (file_name) {
        f = fopen(file_name, "w");
        if (f)
            stddebug = f;
    }
}

void set_log_level(void)
{
    char level[128] = { 0 };
    char *end_ptr = NULL;
    const char *tmp_ptr = NULL;
    unsigned long value = 0;

    tmp_ptr = getenv("EL2GO_LOG_LEVEL");

    if (tmp_ptr) {
        (void)strncpy(level, tmp_ptr, sizeof(level) - 1);
        value = strtoul(level, &end_ptr, 0);
        if (!value && end_ptr == level)
            return;

        if (SET_OVERFLOW(value, log_level))
            log_level = DBG_LEVEL_NONE;
    }
}

void osal_printf(unsigned int level, const char *fmt, ...)
{
    va_list args;
    FILE *debug_stream = NULL;

    if (level > log_level)
        return;

    debug_stream = get_debug_stream();

    va_start(args, fmt);
    (void)vfprintf(debug_stream, fmt, args);
    va_end(args);
    (void)fflush(debug_stream);
}

void osal_printf_always(const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    (void)vfprintf(stdout, fmt, args);
    va_end(args);
    (void)fflush(stdout);
}

int osal_sprintf(char *str, const char *format, ...)
{
    va_list args;
    int ret = 0;

    if (!str || !format)
        return -1;

    va_start(args, format);
    ret = vsprintf(str, format, args);
    va_end(args);

    if (ret < 0)
        return -1;

    return ret;
}

int osal_snprintf(char *str, size_t size, const char *format, ...)
{
    va_list args;
    int ret = 0;

    if (!str || !format || size == 0)
        return -1;

    va_start(args, format);
    ret = vsnprintf(str, size, format, args);
    va_end(args);

    if (ret < 0)
        return -1;

    return ret;
}

void osal_hex_dump(unsigned int level, const void *buffer, size_t length)
{
    const unsigned char *buf = (const unsigned char *)buffer;
    FILE *debug_stream = NULL;
    size_t i = 0;

    if (level > log_level)
        return;

    debug_stream = get_debug_stream();

    if (!buffer) {
        (void)fprintf(debug_stream, "(null)\n");
        return;
    }

    if (!length) {
        (void)fprintf(debug_stream, "(empty)\n");
        return;
    }

    for (; i < length; i++) {
        (void)fprintf(debug_stream, "%02x", buf[i]);

        if ((i + 1) % HEX_DUMP_LINE_LENGTH == 0)
            (void)fprintf(debug_stream, "\n");
        else if (i < length - 1)
            (void)fprintf(debug_stream, " ");
    }

    if (length % HEX_DUMP_LINE_LENGTH)
        (void)fprintf(debug_stream, "\n");

    (void)fflush(debug_stream);
}
