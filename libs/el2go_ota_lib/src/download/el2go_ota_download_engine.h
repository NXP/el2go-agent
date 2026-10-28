/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef __EL2GO_OTA_DOWNLOAD_ENGINE_H__
#define __EL2GO_OTA_DOWNLOAD_ENGINE_H__

/** @defgroup el2go_ota_download_engine OTA Download Engine Internal API
 * @brief Internal API for checking updates and downloading OTA packages.
 * @{
 */

#include <stdint.h>
#include <stddef.h>

#include "ota/el2go_ota_lib.h"
#include "el2go_ota_transport.h"
#include "el2go_ota_request_builder.h"
#include "el2go_ota_response_handler.h"
#include "compiler.h"

/* Retry policy constants for el2go_ota_download_engine_fetch_package(). */
#define EL2GO_OTA_DOWNLOAD_MAX_RETRIES 3U
#define EL2GO_OTA_DOWNLOAD_RETRY_BASE_MS 500U

/**
 * @brief Internal implementation of el2go_ota_check_for_updates().
 *
 * @param[in]  transport   Initialised transport instance. Must not be NULL.
 * @param[in]  attrs       Device attribute array. May be NULL if attr_count is 0.
 * @param[in]  attr_count  Number of entries in attrs[].
 * @param[out] out_resp    Parsed response. Guaranteed non-NULL by caller.
 * @retval EL2GO_OTA_SUCCESS on success.
 * @retval EL2GO_OTA_ERROR_ENCODE on request encoding failure.
 * @retval EL2GO_OTA_ERROR_NETWORK on send/receive failure.
 * @retval EL2GO_OTA_ERROR_DECODE on response parsing failure.
 */
__export el2go_ota_status_t el2go_ota_download_engine_check_for_updates(
    el2go_ota_transport_t *transport, const el2go_ota_attr_t *attrs, size_t attr_count,
    el2go_ota_check_update_resp_t *out_resp);

/**
 * @brief Internal implementation of el2go_ota_download_package().
 *
 * @param[in] transport        Initialised transport instance. Must not be NULL.
 * @param[in] update_id        Update identifier. Guaranteed non-NULL by caller.
 * @param[in] package_id       Package identifier. Guaranteed non-NULL by caller.
 * @param[in] file_id          File identifier within the package. Guaranteed non-NULL by caller.
 * @param[in] resume_offset    Byte offset to resume from (0 = start fresh).
 * @param[in] known_file_size  Known total file size in bytes, or <= 0 if unknown.
 *                             When > 0 the very first range request is clamped to
 *                             [resume_offset, known_file_size - 1] immediately,
 *                             which prevents an out-of-bounds request for files
 *                             that fit in one chunk or when the resume offset lands
 *                             inside the last partial chunk.  When <= 0 the total
 *                             size is learned reactively from the first server
 *                             response (fallback for resume paths with no prior
 *                             check_for_updates() in the current session).
 *                             When > 0 and resume_offset equals it, nothing is fetched
 *                             (SUCCESS, 0 bytes delivered); when resume_offset exceeds
 *                             it, INVALID_PARAM is returned and nothing is sent.
 * @param[in] chunk_cb         Chunk delivery callback. Guaranteed non-NULL by caller.
 * @param[in] cb_ctx           Opaque context for chunk_cb. May be NULL.
 * @retval EL2GO_OTA_SUCCESS on success.
 * @retval EL2GO_OTA_ERROR_INVALID_PARAM on a NULL argument, or if known_file_size > 0 and
 *         resume_offset > known_file_size.
 * @retval EL2GO_OTA_ERROR_ENCODE on encoding failure (not retried).
 * @retval EL2GO_OTA_ERROR_NETWORK on unrecoverable network failure after retries.
 * @retval EL2GO_OTA_ERROR_DECODE on decoding failure (not retried).
 */
__export el2go_ota_status_t el2go_ota_download_engine_fetch_package(
    el2go_ota_transport_t *transport, const char *update_id, const char *package_id,
    const char *file_id, size_t resume_offset, int64_t known_file_size,
    el2go_ota_status_t (*chunk_cb)(const uint8_t *data, size_t len, size_t offset, void *ctx),
    void *cb_ctx);

/** @} */ /* end of el2go_ota_download_engine */

#endif /* __EL2GO_OTA_DOWNLOAD_ENGINE_H__ */
