/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright 2026 NXP
 */

#ifndef __OSAL_H__
#define __OSAL_H__

#include <stddef.h>
#include <stdarg.h>

#include "common/el2go_status.h"

/* Debug levels */
// clang-format off
#define DBG_LEVEL_NONE    0 /* No trace */
#define DBG_LEVEL_ERROR   1 /* Failures of which the user must be aware */
#define DBG_LEVEL_INFO    2 /* Traces which could interest the user */
#define DBG_LEVEL_DEBUG   3 /* First level of debugging information */
#define DBG_LEVEL_VERBOSE 4 /* Second level of debugging information */
#define DBG_LEVEL_EXTRA   5 /* Maximum level of debugging information */
// clang-format on

/**
 * File seek origin - Specifies the reference position for file seeking
 *
 * @OSAL_SEEK_SET: Seek from the beginning of the file
 * @OSAL_SEEK_CUR: Seek from the current file position
 * @OSAL_SEEK_END: Seek from the end of the file
 */
typedef enum {
	OSAL_SEEK_SET = 0,
	OSAL_SEEK_CUR,
	OSAL_SEEK_END
} osal_seek_origin_t;

/* Opaque file handle */
typedef struct osal_file osal_file_t;

/**
 * osal_malloc - Allocate memory
 *
 * @size: Size in bytes to allocate
 *
 * Return:
 * void* pointer to allocated memory or NULL on failure
 */
void *osal_malloc(size_t size);

/**
 * osal_calloc - Allocate and zero-initialize memory
 *
 * @nmemb: Number of elements to allocate
 * @size: Size in bytes of each element
 *
 * Return:
 * void* pointer to allocated memory or NULL on failure
 */
void *osal_calloc(size_t nmemb, size_t size);

/**
 * osal_free - Free allocated memory
 *
 * @ptr: Pointer to memory to free
 *
 * Return:
 * none.
 */
void osal_free(void *ptr);

/**
 * osal_printf - Log formatted output
 *
 * @level: Log level for this message
 * @fmt: Printf-style format string
 * @...: Variable arguments for format string
 *
 * Return:
 * none.
 */
void osal_printf(unsigned int level, const char *fmt, ...);

/**
 * osal_snprintf - Format string into buffer
 *
 * @str: Destination buffer
 * @size: Size of destination buffer
 * @format: Printf-style format string
 * @...: Variable arguments for format string
 *
 * Return:
 * Number of characters written (excluding null terminator), or negative on error
 */
int osal_snprintf(char *str, size_t size, const char *format, ...);

/**
 * osal_hex_dump - Dump buffer hexadecimal contents on a single line
 *
 * @level: Log level for this message
 * @buffer: Pointer to buffer to dump
 * @length: Length of buffer in bytes
 *
 * Return:
 * none.
 */
void osal_hex_dump(unsigned int level, const void *buffer, size_t length);

/**
 * osal_fopen - Open a file
 *
 * @filename: Path to the file to open
 * @mode: File access mode
 *
 * Return:
 * Pointer to osal_file_t on success, NULL on failure
 */
osal_file_t *osal_fopen(const char *filename, const char *mode);

/**
 * osal_fclose - Close a file
 *
 * @file: Pointer to file handle to close
 *
 * Return:
 * error code.
 */
el2go_status_t osal_fclose(osal_file_t *file);

/**
 * osal_fread - Read data from a file
 *
 * @ptr: Pointer to buffer where data will be stored
 * @size: Size of each element to read
 * @nmemb: Number of elements to read
 * @file: Pointer to file handle
 *
 * Return:
 * Number of elements successfully read
 */
size_t osal_fread(void *ptr, size_t size, size_t nmemb, osal_file_t *file);

/**
 * osal_fwrite - Write data to a file
 *
 * @ptr: Pointer to buffer containing data to write
 * @size: Size of each element to write
 * @nmemb: Number of elements to write
 * @file: Pointer to file handle
 *
 * Return:
 * Number of elements successfully written
 */
size_t osal_fwrite(const void *ptr, size_t size, size_t nmemb,
		   osal_file_t *file);

/**
 * osal_fseek - Set file position indicator
 *
 * @file: Pointer to file handle
 * @offset: Number of bytes to offset from origin
 * @origin: Position from where offset is added (OSAL_SEEK_SET, OSAL_SEEK_CUR,
 *          or OSAL_SEEK_END)
 *
 * Return:
 * error code.
 */
el2go_status_t osal_fseek(osal_file_t *file, long offset,
			  osal_seek_origin_t origin);

/**
 * osal_ftell - Get current file position
 *
 * @file: Pointer to file handle
 *
 * Return:
 * Current file position in bytes from beginning of file, or -1 on error
 */
long osal_ftell(osal_file_t *file);

/**
 * osal_fflush - Flush file output buffers
 *
 * @file: Pointer to file handle
 *
 * Return:
 * error code.
 */
el2go_status_t osal_fflush(osal_file_t *file);

/**
 * osal_lib_init - Initialize OSAL subsystem
 *
 * Return:
 * none.
 */
void osal_lib_init(void);

#endif /* __OSAL_H__ */
