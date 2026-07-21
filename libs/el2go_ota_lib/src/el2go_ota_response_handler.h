/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef EL2GO_OTA_RESPONSE_HANDLER_H
#define EL2GO_OTA_RESPONSE_HANDLER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "ota/el2go_ota_lib.h"

typedef el2go_ota_package_info_t el2go_ota_pkg_metadata_t;

/* Parsed structs for FetchFile response */

/**
 * @brief Result of parsing a FetchFile (FileResponse) response.
 *
 * The FileResponse carries: rangeStart, rangeEnd, and raw bytes data.
 * data_ptr points zero-copy into the caller-supplied wire buffer.
 * The caller must keep the wire buffer alive for as long as data_ptr is used.
 */
typedef struct {
    int64_t range_start;     /**< Echo of the requested rangeStart. */
    int64_t range_end;       /**< Echo of the requested rangeEnd. */
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
 * @return EL2GO_OTA_SUCCESS on success (including empty updates list).
 * @return EL2GO_OTA_ERROR_INVALID_PARAM if buf or out is NULL (and buf_len > 0).
 * @return EL2GO_OTA_ERROR_DECODE if nanopb decoding fails.
 */
el2go_ota_status_t el2go_ota_parse_check_update_response(const uint8_t *buf, size_t buf_len,
                                                         el2go_ota_check_update_resp_t *out);

/**
 * @brief Parse a FileResponse from a wire buffer.
 *
 * out->data_ptr points zero-copy into buf. The caller must keep buf alive.
 *
 * @param[in]  buf      Wire buffer. Must not be NULL.
 * @param[in]  buf_len  Length of buf. Must be > 0.
 * @param[out] out      Parsed result. Must not be NULL.
 * @return EL2GO_OTA_SUCCESS on success.
 * @return EL2GO_OTA_ERROR_INVALID_PARAM if buf or out is NULL, or buf_len == 0.
 * @return EL2GO_OTA_ERROR_DECODE if nanopb decoding fails.
 */
el2go_ota_status_t el2go_ota_parse_fetch_package_response(const uint8_t *buf, size_t buf_len,
                                                          el2go_ota_fetch_pkg_resp_t *out);

/**
 * @brief Validate an UpdateStatusNotificationResponse wire buffer.
 *
 * The response is google.protobuf.Empty (zero bytes on the wire). This
 * function simply verifies the buffer decodes without error.
 *
 * @param[in] buf      Wire buffer. May be NULL if buf_len is 0.
 * @param[in] buf_len  Length of buf. May be 0 for empty response.
 * @return EL2GO_OTA_SUCCESS on success.
 * @return EL2GO_OTA_ERROR_DECODE if nanopb decoding fails.
 */
el2go_ota_status_t el2go_ota_parse_report_status_response(const uint8_t *buf, size_t buf_len);

#endif /* EL2GO_OTA_RESPONSE_HANDLER_H */
