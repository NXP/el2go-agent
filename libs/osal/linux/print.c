// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2024, 2026 NXP
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
static FILE *stddebug;

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

	if (level > log_level)
		return;

	va_start(args, fmt);
	(void)vfprintf(stddebug, fmt, args);
	va_end(args);
	(void)fflush(stddebug);
}

void osal_hex_dump(unsigned int level, const void *buffer, size_t length)
{
	const unsigned char *buf = (const unsigned char *)buffer;
	size_t i = 0;

	if (level > log_level)
		return;

	if (!buffer) {
		(void)fprintf(stddebug, "(null)\n");
		return;
	}

	if (!length) {
		(void)fprintf(stddebug, "(empty)\n");
		return;
	}

	for (; i < length; i++) {
		(void)fprintf(stddebug, "%02x", buf[i]);

		if ((i + 1) % HEX_DUMP_LINE_LENGTH == 0)
			(void)fprintf(stddebug, "\n");
		else if (i < length - 1)
			(void)fprintf(stddebug, " ");
	}

	if (length % HEX_DUMP_LINE_LENGTH)
		(void)fprintf(stddebug, "\n");

	(void)fflush(stddebug);
}
