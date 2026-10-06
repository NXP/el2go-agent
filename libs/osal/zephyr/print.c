/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <stdarg.h>
#include <stdio.h>
#include <zephyr/sys/printk.h>
#include "osal.h"

#define HEX_DUMP_LINE_LENGTH 16

/* Default to INFO level (ERROR + INFO) when the build system does not set
 * TRACE_LEVEL explicitly. 
 */
#ifndef TRACE_LEVEL
#define TRACE_LEVEL 2
#endif

static const unsigned int s_log_level = TRACE_LEVEL;

void osal_printf(unsigned int level, const char *fmt, ...)
{
    va_list args;

    if (level == DBG_LEVEL_NONE || level > s_log_level)
        return;

    va_start(args, fmt);
    vprintk(fmt, args);
    va_end(args);
}

void osal_printf_always(const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    vprintk(fmt, args);
    va_end(args);
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

    return (ret < 0) ? -1 : ret;
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

    return (ret < 0) ? -1 : ret;
}

void osal_hex_dump(unsigned int level, const void *buffer, size_t length)
{
    const unsigned char *buf = (const unsigned char *)buffer;
    size_t i = 0;

    if (level == DBG_LEVEL_NONE || level > s_log_level)
        return;

    if (!buffer) {
        printk("(null)\n");
        return;
    }

    if (!length) {
        printk("(empty)\n");
        return;
    }

    for (; i < length; i++) {
        printk("%02x", buf[i]);
        if ((i + 1) % HEX_DUMP_LINE_LENGTH == 0)
            printk("\n");
        else if (i < length - 1)
            printk(" ");
    }

    if (length % HEX_DUMP_LINE_LENGTH)
        printk("\n");
}
