/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef EL2GO_TEST_MOCK_TRANSPORT_H
#define EL2GO_TEST_MOCK_TRANSPORT_H

/** @defgroup test_mock_transport Mock Transport for Component Tests
 * @brief Mock transport implementation for OTA component tests.
 * @{
 */
#include <stddef.h>
#include <stdint.h>

#include "el2go_ota_transport.h"

/**
 * @brief Initialise a transport instance with the mock vtable.
 *
 * @param[out] t  Transport struct to initialise. Must not be NULL.
 * @return EL2GO_OTA_SUCCESS on success, EL2GO_OTA_ERROR_INVALID_PARAM if t is NULL.
 */
el2go_ota_status_t mock_transport_init(el2go_ota_transport_t *t);

/** Reset all queued responses and captured request state. */
void mock_transport_reset(void);

/**
 * @brief Queue one canned response to be returned by the next recv() call.
 *
 * Responses are returned FIFO. Each queued entry is consumed by exactly one
 * recv(). A recv() with no queued response returns a network error.
 *
 * @param[in] data  Response payload bytes (copied). May be NULL if len == 0.
 * @param[in] len   Payload length in bytes.
 * @return 0 on success, non-zero if the queue is full or copy fails.
 */
int mock_transport_queue_response(const uint8_t *data, size_t len);

/**
 * @brief Force the next recv() to return a network error (simulate drop).
 *
 * @return 0 on success, non-zero if the queue is full.
 */
int mock_transport_queue_network_error(void);

/**
 * @brief Copy the most recently sent request payload for wire assertions.
 *
 * @param[out] buf       Output buffer. Must not be NULL.
 * @param[in]  buf_size  Size of buf in bytes.
 * @param[out] out_len   Number of bytes copied. Must not be NULL.
 * @return 0 on success, non-zero if no request has been sent or buf too small.
 */
int mock_transport_get_last_request(uint8_t *buf, size_t buf_size, size_t *out_len);

/** @return Number of send() calls observed since the last reset. */
size_t mock_transport_send_count(void);

/** @} */ /* end of test_mock_transport */

#endif /* EL2GO_TEST_MOCK_TRANSPORT_H */
