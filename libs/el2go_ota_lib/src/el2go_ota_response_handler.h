/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef __EL2GO_OTA_RESPONSE_HANDLER_H__
#define __EL2GO_OTA_RESPONSE_HANDLER_H__

/** @defgroup el2go_ota_response_handler OTA Response Handler Internal API
 * @brief Internal API for parsing protobuf OTA response messages.
 * @{
 */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "ota/el2go_ota_lib.h"
#include "compiler.h"

typedef el2go_ota_package_info_t el2go_ota_pkg_metadata_t;

/* Parsed structs for FetchFile response */

/**
 * @brief Result of parsing a FetchFile (FileResponse) response.
 *
 * The FileResponse carries: totalFileSize, a nested Range (range.start /
 * range.end), and raw bytes data.
 * data_ptr points zero-copy into the caller-supplied wire buffer.
 * The caller must keep the wire buffer alive for as long as data_ptr is used.
 */
typedef struct {
    int64_t total_file_size; /**< Total size of the whole file (from FileResponse.totalFileSize). */
    int64_t range_start; /**< Echo of the requested range start (from FileResponse.range.start). */
    int64_t range_end;   /**< Echo of the requested range end (from FileResponse.range.end). */
    const uint8_t *data_ptr; /**< Zero-copy pointer into wire buffer. */
    size_t data_len;         /**< Length of data in bytes. */
} el2go_ota_fetch_pkg_resp_t;

/* Legacy chunk API compatibility. */
typedef struct {
    const uint8_t *data;
    size_t len;
} el2go_ota_chunk_t;

/* Public API */

/**
 * @brief Parse an AvailableUpdatesResponse from a wire buffer.
 *
 * @param[in]  buf      Wire buffer. May be non-NULL even when buf_len == 0.
 * @param[in]  buf_len  Length of buf. 0 means empty response (no updates).
 * @param[out] out      Parsed result. Must not be NULL.
 * @retval EL2GO_OTA_SUCCESS on success (including empty updates list).
 * @retval EL2GO_OTA_ERROR_INVALID_PARAM if buf or out is NULL (and buf_len > 0).
 * @retval EL2GO_OTA_ERROR_DECODE if nanopb decoding fails.
 */
__export el2go_ota_status_t el2go_ota_parse_check_update_response(
    const uint8_t *buf, size_t buf_len, el2go_ota_check_update_resp_t *out);

/**
 * @brief Parse a FileResponse from a wire buffer.
 *
 * out->data_ptr points zero-copy into buf. The caller must keep buf alive.
 *
 * @param[in]  buf      Wire buffer. Must not be NULL.
 * @param[in]  buf_len  Length of buf. Must be > 0.
 * @param[out] out      Parsed result. Must not be NULL.
 * @retval EL2GO_OTA_SUCCESS on success.
 * @retval EL2GO_OTA_ERROR_INVALID_PARAM if buf or out is NULL, or buf_len == 0.
 * @retval EL2GO_OTA_ERROR_DECODE if nanopb decoding fails.
 */
__export el2go_ota_status_t el2go_ota_parse_fetch_package_response(const uint8_t *buf,
                                                                   size_t buf_len,
                                                                   el2go_ota_fetch_pkg_resp_t *out);

/**
 * @brief Validate an UpdateStatusNotificationResponse wire buffer.
 *
 * The response is google.protobuf.Empty (zero bytes on the wire). This
 * function simply verifies the buffer decodes without error.
 *
 * @param[in] buf      Wire buffer. May be NULL if buf_len is 0.
 * @param[in] buf_len  Length of buf. May be 0 for empty response.
 * @retval EL2GO_OTA_SUCCESS on success.
 * @retval EL2GO_OTA_ERROR_DECODE if nanopb decoding fails.
 */
__export el2go_ota_status_t el2go_ota_parse_report_status_response(const uint8_t *buf,
                                                                   size_t buf_len);

/** @} */ /* end of el2go_ota_response_handler */

#endif /* __EL2GO_OTA_RESPONSE_HANDLER_H__ */
