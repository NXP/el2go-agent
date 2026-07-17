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

/* String length limits (all include the null terminator) */

#define EL2GO_OTA_MAX_UPDATE_ID_LEN 64U
#define EL2GO_OTA_MAX_PACKAGE_ID_LEN 64U
#define EL2GO_OTA_MAX_FILE_ID_LEN 64U
#define EL2GO_OTA_MAX_NAME_LEN 128U
#define EL2GO_OTA_MAX_VERSION_LEN 32U
#define EL2GO_OTA_MAX_CHECKSUM_LEN 128U

/* Maximum number of entries stored per level of the hierarchy. */
#define EL2GO_OTA_MAX_UPDATES 4U
#define EL2GO_OTA_MAX_PACKAGES 4U
#define EL2GO_OTA_MAX_FILE_METADATA 8U

/* Parsed structs for GetAvailableUpdates response */

/**
 * @brief Parsed FileMetadata entry from an Update/Package hierarchy.
 */
typedef struct {
    char file_id[EL2GO_OTA_MAX_FILE_ID_LEN];
    char name[EL2GO_OTA_MAX_NAME_LEN];
    int64_t size; /**< File size in bytes. */
    char checksum[EL2GO_OTA_MAX_CHECKSUM_LEN];
} el2go_ota_file_metadata_t;

/**
 * @brief Parsed Package entry inside an Update.
 */
typedef struct {
    char package_id[EL2GO_OTA_MAX_PACKAGE_ID_LEN];
    char name[EL2GO_OTA_MAX_NAME_LEN];
    char version[EL2GO_OTA_MAX_VERSION_LEN];
    el2go_ota_file_metadata_t files[EL2GO_OTA_MAX_FILE_METADATA];
    size_t file_count;
} el2go_ota_package_info_t;

/**
 * @brief Parsed Update entry from an AvailableUpdatesResponse.
 */
typedef struct {
    char update_id[EL2GO_OTA_MAX_UPDATE_ID_LEN];
    char name[EL2GO_OTA_MAX_NAME_LEN];
    el2go_ota_package_info_t packages[EL2GO_OTA_MAX_PACKAGES];
    size_t package_count;
} el2go_ota_update_info_t;

/**
 * @brief Result of parsing a GetAvailableUpdates response.
 */
typedef struct {
    bool update_available; /**< true if updates[] is non-empty. */
    el2go_ota_update_info_t updates[EL2GO_OTA_MAX_UPDATES];
    size_t update_count; /**< Number of valid entries in updates[]. */

    /* Convenience alias: first package of first update (most common use). */
    const char *first_update_id;  /**< Points into updates[0].update_id. */
    const char *first_package_id; /**< Points into updates[0].packages[0].package_id. */
} el2go_ota_check_update_resp_t;

/* Legacy compatibility: the old API used el2go_ota_pkg_metadata_t and
 * packages[] array directly. Provide a thin alias so callers that only use
 * the first update/package still compile unchanged. */
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
