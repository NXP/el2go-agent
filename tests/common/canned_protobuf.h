/*
 * Copyright 2018-2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef EL2GO_TEST_CANNED_PROTOBUF_H
#define EL2GO_TEST_CANNED_PROTOBUF_H

#include <stddef.h>
#include <stdint.h>

/**
 * @brief Build an AvailableUpdatesResponse with one Update and one Package.
 *
 * @param[out] buf       Output buffer. Must not be NULL.
 * @param[in]  buf_size  Size of buf in bytes.
 * @param[out] out_len   Number of bytes written. Must not be NULL.
 * @return 0 on success, non-zero on encode error.
 */
int canned_check_update_one_package(uint8_t *buf, size_t buf_size, size_t *out_len);

/**
 * @brief Build an empty AvailableUpdatesResponse (no updates available).
 *
 * @param[out] buf       Output buffer. Must not be NULL.
 * @param[in]  buf_size  Size of buf in bytes.
 * @param[out] out_len   Number of bytes written (may be 0). Must not be NULL.
 * @return 0 on success, non-zero on encode error.
 */
int canned_check_update_empty(uint8_t *buf, size_t buf_size, size_t *out_len);

/**
 * @brief Build a FileResponse carrying one chunk of package data.
 *
 * @param[out] buf          Output buffer. Must not be NULL.
 * @param[in]  buf_size     Size of buf in bytes.
 * @param[in]  range_start  Byte offset of the first payload byte.
 * @param[in]  range_end    Byte offset of the last payload byte (inclusive).
 * @param[in]  data         Chunk payload. Must not be NULL if data_len > 0.
 * @param[in]  data_len     Payload length in bytes.
 * @param[out] out_len      Number of bytes written. Must not be NULL.
 * @return 0 on success, non-zero on encode error.
 */
int canned_fetch_package_chunk(uint8_t *buf, size_t buf_size, int64_t range_start,
                               int64_t range_end, const uint8_t *data, size_t data_len,
                               size_t *out_len);

/**
 * @brief Build an empty UpdateStatusNotification acknowledgement.
 *
 * @param[out] buf       Output buffer. Must not be NULL.
 * @param[in]  buf_size  Size of buf in bytes.
 * @param[out] out_len   Number of bytes written (may be 0). Must not be NULL.
 * @return 0 on success, non-zero on encode error.
 */
int canned_report_status_ack(uint8_t *buf, size_t buf_size, size_t *out_len);

#endif /* EL2GO_TEST_CANNED_PROTOBUF_H */
