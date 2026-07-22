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

#include <zephyr/kvss/nvs.h>
#include <zephyr/storage/flash_map.h>
#include <zephyr/drivers/flash.h>

#include "el2go_ota_kvs.h"
#include "debug.h"

/* Devicetree helpers -- same pattern used by fwual_mcuboot.c */
#define PARTITION_DEVICE(label) DEVICE_DT_GET(DT_MTD_FROM_FIXED_PARTITION(DT_NODELABEL(label)))
#define PARTITION_OFFSET(label) DT_REG_ADDR(DT_NODELABEL(label))
#define PARTITION_SIZE(label) DT_REG_SIZE(DT_NODELABEL(label))

static struct nvs_fs s_kvs_nvs;
static bool s_kvs_ready;

el2go_ota_status_t el2go_ota_kvs_init(void)
{
    struct flash_pages_info info = { 0 };
    el2go_ota_status_t result = EL2GO_OTA_ERROR_INTERNAL;
    int rc = 0;

    if (s_kvs_ready) {
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
    s_kvs_nvs.sector_count =
        (uint16_t)(PARTITION_SIZE(ota_status_partition) / s_kvs_nvs.sector_size);

    rc = nvs_mount(&s_kvs_nvs);
    if (rc != 0) {
        EL2GO_DBG_PRINTF(ERROR, "nvs_mount failed: %d\n", rc);
        result = EL2GO_OTA_ERROR_INTERNAL;
        goto exit;
    }

    s_kvs_ready = true;

exit:
    return result;
}

el2go_ota_status_t el2go_ota_kvs_write(uint16_t key, const void *data, size_t len)
{
    ssize_t rc = nvs_write(&s_kvs_nvs, key, data, len);

    if (rc < 0) {
        EL2GO_DBG_PRINTF(ERROR, "nvs_write key=%u failed: %d\n", (unsigned)key, (int)rc);
        return EL2GO_OTA_ERROR_INTERNAL;
    }
    return EL2GO_OTA_SUCCESS;
}

el2go_ota_status_t el2go_ota_kvs_read(uint16_t key, void *data, size_t len, bool *found)
{
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
