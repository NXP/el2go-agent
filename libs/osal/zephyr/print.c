/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <stdarg.h>
#include <stdio.h>
#include "osal.h"

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(el2go_osal, CONFIG_LOG_DEFAULT_LEVEL);

#define HEX_DUMP_LINE_LENGTH 16

void osal_printf(unsigned int level, const char *fmt, ...)
{
    va_list args;
    char buf[256] = { 0 };

    if (level == DBG_LEVEL_NONE) {
        return;
    }

    va_start(args, fmt);
    (void)vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    switch (level) {
    case DBG_LEVEL_ERROR:
        LOG_ERR("%s", buf);
        break;
    case DBG_LEVEL_INFO:
        LOG_INF("%s", buf);
        break;
    case DBG_LEVEL_DEBUG:
        LOG_DBG("%s", buf);
        break;
    case DBG_LEVEL_VERBOSE:
    case DBG_LEVEL_EXTRA:
        LOG_DBG("%s", buf);
        break;
    default:
        break;
    }
}

void osal_printf_always(const char *fmt, ...)
{
    va_list args;
    char buf[256] = { 0 };

    va_start(args, fmt);
    (void)vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    LOG_INF("%s", buf);
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

    if (level == DBG_LEVEL_NONE)
        return;
    if (!buffer) {
        osal_printf(level, "(null)\n");
        return;
    }
    if (!length) {
        osal_printf(level, "(empty)\n");
        return;
    }

    for (; i < length; i++) {
        osal_printf(level, "%02x", buf[i]);
        if ((i + 1) % HEX_DUMP_LINE_LENGTH == 0)
            osal_printf(level, "\n");
        else if (i < length - 1)
            osal_printf(level, " ");
    }
    if (length % HEX_DUMP_LINE_LENGTH)
        osal_printf(level, "\n");
}
