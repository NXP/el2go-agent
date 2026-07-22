/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef __EL2GO_OTA_REQUEST_BUILDER_H__
#define __EL2GO_OTA_REQUEST_BUILDER_H__

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "ota/el2go_ota_lib.h"

/**
 * @brief Input for encoding a GetAvailableUpdates request.
 *
 * Uses el2go_ota_attr_t from ota/el2go_ota_lib.h (included via the public header).
 */
typedef struct {
    const el2go_ota_attr_t *attrs; /**< Array of device attribute pairs. */
    size_t attr_count;             /**< Number of entries in attrs[]. */
} el2go_ota_check_update_req_t;

/**
 * @brief Input for encoding a FetchFile (FileRequest) request.
 *
 * update_id and package_id are mandatory. artifact_id may be NULL or empty
 * (the server will select the default artifact). range_start and range_end
 * are byte offsets for chunked download; set has_range_start / has_range_end
 * to false to omit them (full-file download).
 */
typedef struct {
    const char *update_id;   /**< Must not be NULL. */
    const char *package_id;  /**< Must not be NULL. */
    const char *artifact_id; /**< Optional artifact selector. May be NULL. */
    bool has_range_start;    /**< Set true to include rangeStart in the request. */
    int64_t range_start;     /**< First byte offset of the requested chunk. */
    bool has_range_end;      /**< Set true to include rangeEnd in the request. */
    int64_t range_end;       /**< Last byte offset (inclusive) of the requested chunk. */
} el2go_ota_fetch_pkg_req_t;

/**
 * @brief Update status values for ReportUpdateStatus.
 *
 * Matches the server-side Status enum:
 *   STATUS_UNSPECIFIED = 0, STATUS_SUCCESS = 1,
 *   STATUS_ERROR = 2, STATUS_ROLLED_BACK = 3.
 */
typedef enum {
    EL2GO_OTA_UPDATE_STATUS_UNSPECIFIED = 0,
    EL2GO_OTA_UPDATE_STATUS_SUCCESS = 1,
    EL2GO_OTA_UPDATE_STATUS_ERROR = 2,
    EL2GO_OTA_UPDATE_STATUS_ROLLED_BACK = 3,
} el2go_ota_update_status_t;

/**
 * @brief Input for encoding a ReportUpdateStatus request.
 *
 * Matches UpdateStatusNotification: only updateId + status + optional message.
 * There is no packageId field on the server-side message.
 */
typedef struct {
    const char *update_id;            /**< Must not be NULL. */
    el2go_ota_update_status_t status; /**< Update outcome. */
    const char *status_message;       /**< Optional human-readable detail. May be NULL. */
} el2go_ota_report_status_req_t;

/**
 * @brief Encode an AvailableUpdatesRequest into a flat byte buffer.
 *
 * @param[in]  req      Request input. Must not be NULL.
 * @param[out] buf      Output buffer. Must not be NULL.
 * @param[in]  buf_len  Size of buf in bytes.
 * @param[out] out_len  Number of bytes written. Must not be NULL.
 * @return EL2GO_OTA_SUCCESS on success.
 * @return EL2GO_OTA_ERROR_INVALID_PARAM if req, buf, or out_len is NULL.
 * @return EL2GO_OTA_ERROR_ENCODE if nanopb encoding fails or buf is too small.
 */
el2go_ota_status_t el2go_ota_encode_check_update(const el2go_ota_check_update_req_t *req,
                                                 uint8_t *buf, size_t buf_len, size_t *out_len);

/**
 * @brief Encode a FileRequest into a flat byte buffer.
 *
 * @param[in]  req      Request input. Must not be NULL.
 * @param[out] buf      Output buffer. Must not be NULL.
 * @param[in]  buf_len  Size of buf in bytes.
 * @param[out] out_len  Number of bytes written. Must not be NULL.
 * @return EL2GO_OTA_SUCCESS on success.
 * @return EL2GO_OTA_ERROR_INVALID_PARAM if req, buf, out_len, update_id,
 *         or package_id is NULL.
 * @return EL2GO_OTA_ERROR_ENCODE if nanopb encoding fails or buf is too small.
 */
el2go_ota_status_t el2go_ota_encode_fetch_package(const el2go_ota_fetch_pkg_req_t *req,
                                                  uint8_t *buf, size_t buf_len, size_t *out_len);

/**
 * @brief Encode an UpdateStatusNotification into a flat byte buffer.
 *
 * @param[in]  req      Request input. Must not be NULL.
 * @param[out] buf      Output buffer. Must not be NULL.
 * @param[in]  buf_len  Size of buf in bytes.
 * @param[out] out_len  Number of bytes written. Must not be NULL.
 * @return EL2GO_OTA_SUCCESS on success.
 * @return EL2GO_OTA_ERROR_INVALID_PARAM if req, buf, out_len, or update_id
 *         is NULL.
 * @return EL2GO_OTA_ERROR_ENCODE if nanopb encoding fails or buf is too small.
 */
el2go_ota_status_t el2go_ota_encode_report_status(const el2go_ota_report_status_req_t *req,
                                                  uint8_t *buf, size_t buf_len, size_t *out_len);

#endif /* __EL2GO_OTA_REQUEST_BUILDER_H__ */
