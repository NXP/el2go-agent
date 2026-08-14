/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef __OSAL_H__
#define __OSAL_H__

#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>

#include "common/el2go_status.h"

/* Debug levels */
#define DBG_LEVEL_NONE 0    /* No trace */
#define DBG_LEVEL_ERROR 1   /* Failures of which the user must be aware */
#define DBG_LEVEL_INFO 2    /* Traces which could interest the user */
#define DBG_LEVEL_DEBUG 3   /* First level of debugging information */
#define DBG_LEVEL_VERBOSE 4 /* Second level of debugging information */
#define DBG_LEVEL_EXTRA 5   /* Maximum level of debugging information */

/**
 * File seek origin - Specifies the reference position for file seeking
 *
 * @OSAL_SEEK_SET: Seek from the beginning of the file
 * @OSAL_SEEK_CUR: Seek from the current file position
 * @OSAL_SEEK_END: Seek from the end of the file
 */
typedef enum { OSAL_SEEK_SET = 0, OSAL_SEEK_CUR, OSAL_SEEK_END } osal_seek_origin_t;

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
 * osal_printf_always - Unconditional formatted output to stdout
 *
 * Bypasses the log level filter entirely. Use for user-requested output
 * (e.g. status reports) that must always be visible.
 *
 * @fmt: Printf-style format string
 * @...: Variable arguments for format string
 *
 * Return:
 * none.
 */
void osal_printf_always(const char *fmt, ...);

/**
 * osal_sprintf - Format string into buffer (unbounded)
 *
 * @str: Destination buffer (must be large enough to hold the result)
 * @format: Printf-style format string
 * @...: Variable arguments for format string
 *
 * Return:
 * Number of characters written (excluding null terminator), or negative on error
 */
int osal_sprintf(char *str, const char *format, ...);

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
size_t osal_fwrite(const void *ptr, size_t size, size_t nmemb, osal_file_t *file);

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
el2go_status_t osal_fseek(osal_file_t *file, long offset, osal_seek_origin_t origin);

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
 * osal_uuid - Retrieve the device UUID into a caller-provided buffer
 *
 * @buf:      Buffer to write the UUID bytes into
 * @buf_len:  Size of @buf in bytes
 * @uuid_len: Set to the actual number of UUID bytes written on success
 *
 * Return:
 * EL2GO_STATUS_SUCCESS on success,
 * EL2GO_STATUS_BUFFER_TOO_SMALL if @buf_len is insufficient,
 * other error code on failure
 */
el2go_status_t osal_uuid(uint8_t *buf, size_t buf_len, size_t *uuid_len);

/**
 * osal_sleep_ms - Sleep for a given number of milliseconds
 *
 * @ms: Number of milliseconds to sleep
 *
 * Return:
 * none.
 */
void osal_sleep_ms(uint32_t ms);

/**
 * osal_lib_init - Initialize OSAL subsystem
 *
 * Return:
 * none.
 */
void osal_lib_init(void);

/**
 * osal_start_task - Run the application entry function in the correct task context
 *
 * On RTOS targets that require work to run inside a task (e.g. FreeRTOS),
 * this spawns a task, starts the scheduler, and returns the task exit code.
 * On targets where main() already runs as a thread (Zephyr, Linux, POSIX),
 * this is a direct passthrough that calls fn(argc, argv) inline.
 *
 * @fn:   Pointer to the function to run
 * @argc: Argument count forwarded from main()
 * @argv: Argument vector forwarded from main()
 *
 * Return:
 * Return value of fn(), or a negative error code on task launch failure.
 */
int osal_start_task(int (*fn)(int argc, const char *argv[]), int argc, const char *argv[]);

#endif /* __OSAL_H__ */