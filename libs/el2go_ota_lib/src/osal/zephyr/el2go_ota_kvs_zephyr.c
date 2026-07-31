/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

/*
 * EL2GO OTA Library -- Zephyr NVS implementation of the KVS abstraction.
 *
 * All persistent state for status reporting is kept in the flash partition
 * labelled ota_status_partition in the board DTS / overlay.
 */

#include <zephyr/device.h>
#include <zephyr/kvss/nvs.h>
#include <zephyr/storage/flash_map.h>
#include <zephyr/drivers/flash.h>

#include "el2go_ota_kvs.h"
#include "debug.h"

static struct nvs_fs s_kvs_nvs;
static bool s_kvs_ready;

el2go_ota_status_t el2go_ota_kvs_init(void)
{
    struct flash_pages_info info = { 0 };
    el2go_ota_status_t result = EL2GO_OTA_ERROR_INTERNAL;
    int rc = 0;

    if (s_kvs_ready) {
        result = EL2GO_OTA_SUCCESS;
        goto exit;
    }

    s_kvs_nvs.flash_device = PARTITION_DEVICE(ota_status_partition);
    if (!device_is_ready(s_kvs_nvs.flash_device)) {
        EL2GO_DBG_PRINTF(ERROR, "ota_status_partition flash device not ready\n");
        result = EL2GO_OTA_ERROR_INTERNAL;
        goto exit;
    }

    s_kvs_nvs.offset = (off_t)PARTITION_OFFSET(ota_status_partition);

    rc = flash_get_page_info_by_offs(s_kvs_nvs.flash_device, s_kvs_nvs.offset, &info);
    if (rc != 0) {
        EL2GO_DBG_PRINTF(ERROR, "flash_get_page_info_by_offs failed: %d\n", rc);
        result = EL2GO_OTA_ERROR_INTERNAL;
        goto exit;
    }

    s_kvs_nvs.sector_size = (uint32_t)info.size;
    if (s_kvs_nvs.sector_size == 0U) {
        EL2GO_DBG_PRINTF(ERROR,
                         "el2go_ota_kvs_init: sector_size is 0, check DTS partition config\n");
        result = EL2GO_OTA_ERROR_INTERNAL;
        goto exit;
    }
    s_kvs_nvs.sector_count =
        (uint16_t)(PARTITION_SIZE(ota_status_partition) / s_kvs_nvs.sector_size);

    rc = nvs_mount(&s_kvs_nvs);
    if (rc != 0) {
        EL2GO_DBG_PRINTF(ERROR, "nvs_mount failed: %d\n", rc);
        result = EL2GO_OTA_ERROR_INTERNAL;
        goto exit;
    }

    s_kvs_ready = true;
    result = EL2GO_OTA_SUCCESS;

exit:
    return result;
}

el2go_ota_status_t el2go_ota_kvs_write(uint16_t key, const void *data, size_t len)
{
    if ((data == NULL) && (len != 0U)) {
        return EL2GO_OTA_ERROR_INVALID_PARAM;
    }

    ssize_t rc = nvs_write(&s_kvs_nvs, key, data, len);

    if (rc < 0) {
        EL2GO_DBG_PRINTF(ERROR, "nvs_write key=%u failed: %d\n", (unsigned)key, (int)rc);
        return EL2GO_OTA_ERROR_INTERNAL;
    }
    /* rc == 0 means the value was already stored unchanged -- nvs_write() skipped the
     * flash write as an optimisation. Treat it as success, not a partial write. */
    if (rc > 0 && (size_t)rc != len) {
        EL2GO_DBG_PRINTF(ERROR, "nvs_write key=%u partial write: %d of %zu bytes\n", (unsigned)key,
                         (int)rc, len);
        return EL2GO_OTA_ERROR_INTERNAL;
    }
    return EL2GO_OTA_SUCCESS;
}

el2go_ota_status_t el2go_ota_kvs_read(uint16_t key, void *data, size_t len, bool *found)
{
    if ((found == NULL) || ((data == NULL) && (len != 0U))) {
        return EL2GO_OTA_ERROR_INVALID_PARAM;
    }

    ssize_t rc = nvs_read(&s_kvs_nvs, key, data, len);

    if (rc == -ENOENT) {
        *found = false;
        return EL2GO_OTA_SUCCESS;
    }
    if (rc < 0) {
        EL2GO_DBG_PRINTF(ERROR, "nvs_read key=%u failed: %d\n", (unsigned)key, (int)rc);
        return EL2GO_OTA_ERROR_INTERNAL;
    }
    *found = true;
    return EL2GO_OTA_SUCCESS;
}

el2go_ota_status_t el2go_ota_kvs_delete(uint16_t key)
{
    int rc = nvs_delete(&s_kvs_nvs, key);

    if (rc < 0 && rc != -ENOENT) {
        EL2GO_DBG_PRINTF(ERROR, "nvs_delete key=%u failed: %d\n", (unsigned)key, rc);
        return EL2GO_OTA_ERROR_INTERNAL;
    }
    return EL2GO_OTA_SUCCESS;
}
