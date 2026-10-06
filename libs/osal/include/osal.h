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

/**
 * @defgroup osal OSAL
 * @brief Operating System Abstraction Layer for memory, I/O, logging, and timing.
 * @{
 */

#define DBG_LEVEL_NONE 0    /**< No trace */
#define DBG_LEVEL_ERROR 1   /**< Failures of which the user must be aware */
#define DBG_LEVEL_INFO 2    /**< Traces which could interest the user */
#define DBG_LEVEL_DEBUG 3   /**< First level of debugging information */
#define DBG_LEVEL_VERBOSE 4 /**< Second level of debugging information */
#define DBG_LEVEL_EXTRA 5   /**< Maximum level of debugging information */

/**
 * @brief File seek origin - specifies the reference position for file seeking.
 */
typedef enum {
    OSAL_SEEK_SET = 0, /**< Seek from the beginning of the file */
    OSAL_SEEK_CUR,     /**< Seek from the current file position */
    OSAL_SEEK_END      /**< Seek from the end of the file */
} osal_seek_origin_t;

/** @brief Opaque file handle. */
typedef struct osal_file osal_file_t;

/**
 * @brief Allocate memory.
 *
 * @param[in] size Size in bytes to allocate
 *
 * @return Pointer to allocated memory, or NULL on failure
 */
void *osal_malloc(size_t size);

/**
 * @brief Allocate and zero-initialize memory.
 *
 * @param[in] nmemb Number of elements to allocate
 * @param[in] size  Size in bytes of each element
 *
 * @return Pointer to allocated memory, or NULL on failure
 */
void *osal_calloc(size_t nmemb, size_t size);

/**
 * @brief Free allocated memory.
 *
 * @param[in] ptr Pointer to memory to free
 */
void osal_free(void *ptr);

/**
 * @brief Log formatted output.
 *
 * @param[in] level Log level for this message
 * @param[in] fmt   Printf-style format string
 * @param[in] ...   Variable arguments for format string
 */
void osal_printf(unsigned int level, const char *fmt, ...);

/**
 * @brief Unconditional formatted output to stdout.
 *
 * Bypasses the log level filter entirely. Use for user-requested output
 * (e.g. status reports) that must always be visible.
 *
 * @param[in] fmt Printf-style format string
 * @param[in] ... Variable arguments for format string
 */
void osal_printf_always(const char *fmt, ...);

/**
 * @brief Format string into buffer (unbounded).
 *
 * @param[out] str    Destination buffer (must be large enough to hold the result)
 * @param[in]  format Printf-style format string
 * @param[in]  ...    Variable arguments for format string
 *
 * @return Number of characters written (excluding null terminator), or negative on error
 */
int osal_sprintf(char *str, const char *format, ...);

/**
 * @brief Format string into buffer.
 *
 * @param[out] str    Destination buffer
 * @param[in]  size   Size of destination buffer
 * @param[in]  format Printf-style format string
 * @param[in]  ...    Variable arguments for format string
 *
 * @return Number of characters written (excluding null terminator), or negative on error
 */
int osal_snprintf(char *str, size_t size, const char *format, ...);

/**
 * @brief Dump buffer hexadecimal contents on a single line.
 *
 * @param[in] level  Log level for this message
 * @param[in] buffer Pointer to buffer to dump
 * @param[in] length Length of buffer in bytes
 */
void osal_hex_dump(unsigned int level, const void *buffer, size_t length);

/**
 * @brief Open a file.
 *
 * @param[in] filename Path to the file to open
 * @param[in] mode     File access mode
 *
 * @return Pointer to osal_file_t on success, NULL on failure
 */
osal_file_t *osal_fopen(const char *filename, const char *mode);

/**
 * @brief Close a file.
 *
 * @param[in] file Pointer to file handle to close
 *
 * @return error code
 */
el2go_status_t osal_fclose(osal_file_t *file);

/**
 * @brief Read data from a file.
 *
 * @param[out] ptr   Pointer to buffer where data will be stored
 * @param[in]  size  Size of each element to read
 * @param[in]  nmemb Number of elements to read
 * @param[in]  file  Pointer to file handle
 *
 * @return Number of elements successfully read
 */
size_t osal_fread(void *ptr, size_t size, size_t nmemb, osal_file_t *file);

/**
 * @brief Write data to a file.
 *
 * @param[in] ptr   Pointer to buffer containing data to write
 * @param[in] size  Size of each element to write
 * @param[in] nmemb Number of elements to write
 * @param[in] file  Pointer to file handle
 *
 * @return Number of elements successfully written
 */
size_t osal_fwrite(const void *ptr, size_t size, size_t nmemb, osal_file_t *file);

/**
 * @brief Set file position indicator.
 *
 * @param[in] file   Pointer to file handle
 * @param[in] offset Number of bytes to offset from origin
 * @param[in] origin Position from where offset is added (OSAL_SEEK_SET,
 *                   OSAL_SEEK_CUR, or OSAL_SEEK_END)
 *
 * @return error code
 */
el2go_status_t osal_fseek(osal_file_t *file, long offset, osal_seek_origin_t origin);

/**
 * @brief Get current file position.
 *
 * @param[in] file Pointer to file handle
 *
 * @return Current file position in bytes from beginning of file, or -1 on error
 */
long osal_ftell(osal_file_t *file);

/**
 * @brief Flush file output buffers.
 *
 * @param[in] file Pointer to file handle
 *
 * @return error code
 */
el2go_status_t osal_fflush(osal_file_t *file);

/**
 * @brief Retrieve the device UUID into a caller-provided buffer.
 *
 * @param[out] buf      Buffer to write the UUID bytes into
 * @param[in]  buf_len  Size of @p buf in bytes
 * @param[out] uuid_len Set to the actual number of UUID bytes written on success
 *
 * @retval EL2GO_STATUS_SUCCESS on success
 * @retval EL2GO_STATUS_BUFFER_TOO_SMALL if @p buf_len is insufficient
 * @retval el2go_status_t other error code on failure
 */
el2go_status_t osal_uuid(uint8_t *buf, size_t buf_len, size_t *uuid_len);

/**
 * @brief Sleep for a given number of milliseconds.
 *
 * @param[in] ms Number of milliseconds to sleep
 */
void osal_sleep_ms(uint32_t ms);

/**
 * @brief Return the number of milliseconds elapsed since boot.
 *
 * @return Monotonic uptime in milliseconds.
 */
int64_t osal_uptime_ms(void);

/**
 * @brief Initialize OSAL subsystem.
 */
void osal_lib_init(void);

/**
 * @brief Run the application entry function in the correct task context.
 *
 * On RTOS targets that require work to run inside a task (e.g. FreeRTOS),
 * this spawns a task, starts the scheduler, and returns the task exit code.
 * On targets where main() already runs as a thread (Zephyr, Linux, POSIX),
 * this is a direct passthrough that calls fn(argc, argv) inline.
 *
 * @param[in] fn   Pointer to the function to run
 * @param[in] argc Argument count forwarded from main()
 * @param[in] argv Argument vector forwarded from main()
 *
 * @return Return value of fn(), or a negative error code on task launch failure
 */
int osal_start_task(int (*fn)(int argc, const char *argv[]), int argc, const char *argv[]);

/** @} */ /* end of osal */

#endif /* __OSAL_H__ */
