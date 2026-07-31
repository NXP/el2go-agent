/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef __EL2GO_OTA_KVS_H__
#define __EL2GO_OTA_KVS_H__

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#include "ota/el2go_ota_lib.h"

/**
 * @brief Initialize the Key-Value Store backend.
 *
 * Must be called before any other el2go_ota_kvs_* function. Calling it more
 * than once is safe -- subsequent calls return EL2GO_OTA_SUCCESS immediately.
 *
 * @return EL2GO_OTA_SUCCESS on success.
 * @return EL2GO_OTA_ERROR_INTERNAL if the flash device is not ready or the
 *         NVS mount fails.
 */
el2go_ota_status_t el2go_ota_kvs_init(void);

/**
 * @brief Write a value to the KVS under the given key.
 *
 * Passing data == NULL with len == 0 is equivalent to a delete and is
 * forwarded directly to the underlying NVS implementation.
 *
 * @param[in] key   Numeric key identifier.
 * @param[in] data  Pointer to the data to write. May be NULL only when len
 *                  is 0 (delete-by-write semantic).
 * @param[in] len   Number of bytes to write. Pass 0 to delete the entry.
 *
 * @return EL2GO_OTA_SUCCESS on success.
 * @return EL2GO_OTA_ERROR_INVALID_PARAM if data is NULL and len is non-zero.
 * @return EL2GO_OTA_ERROR_INTERNAL if the underlying NVS write fails.
 */
el2go_ota_status_t el2go_ota_kvs_write(uint16_t key, const void *data, size_t len);

/**
 * @brief Read a value from the KVS for the given key.
 *
 * Passing data == NULL with len == 0 queries the stored size without copying
 * data, which is supported by the underlying NVS implementation.
 *
 * @param[in]  key    Numeric key identifier.
 * @param[out] data   Buffer to receive the stored value. May be NULL only
 *                    when len is 0 (size-query semantic).
 * @param[in]  len    Size of data buffer in bytes. Pass 0 to query size only.
 * @param[out] found  Set to true if the key exists, false if not found. Must
 *                    not be NULL.
 *
 * @return EL2GO_OTA_SUCCESS on success (key found or not found).
 * @return EL2GO_OTA_ERROR_INVALID_PARAM if found is NULL, or if data is NULL
 *         and len is non-zero.
 * @return EL2GO_OTA_ERROR_INTERNAL if the underlying NVS read fails.
 */
el2go_ota_status_t el2go_ota_kvs_read(uint16_t key, void *data, size_t len, bool *found);

/**
 * @brief Delete the entry for the given key from the KVS.
 *
 * If the key does not exist the function returns EL2GO_OTA_SUCCESS silently.
 *
 * @param[in] key  Numeric key identifier.
 *
 * @return EL2GO_OTA_SUCCESS on success or if the key was not present.
 * @return EL2GO_OTA_ERROR_INTERNAL if the underlying NVS delete fails.
 */
el2go_ota_status_t el2go_ota_kvs_delete(uint16_t key);

#endif /* __EL2GO_OTA_KVS_H__ */
