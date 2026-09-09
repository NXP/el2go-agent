/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

/* Persistence backend: Zephyr NVS on agent_state_partition. This partition is
 * kept separate from storage_partition and ota_status_partition so the agent
 * record is isolated from other stored data. */

#include "el2go_ota_persist.h"

#include <zephyr/kernel.h>
#include <zephyr/kvss/nvs.h>
#include <zephyr/storage/flash_map.h>

#include <zephyr/drivers/flash.h>
#include <zephyr/logging/log.h>

#include <string.h>

LOG_MODULE_REGISTER(persist, CONFIG_LOG_DEFAULT_LEVEL);

/* NVS key that stores the entire agent_persist_t record. */
#define AGENT_PERSIST_NVS_KEY 1U

static struct nvs_fs s_nvs;
static bool s_ready;

/**
 * @brief Mounts the NVS file system on the agent state partition
 *
 * Idempotent. Resolves the flash device and geometry for
 * agent_state_partition, derives the sector size and count, and mounts NVS.
 * Subsequent calls return immediately once mounted.
 *
 * @retval EL2GO_OTA_PERSIST_OK on success.
 * @retval EL2GO_OTA_PERSIST_ERR_NOT_READY if the flash device is not ready.
 * @retval EL2GO_OTA_PERSIST_ERR_MOUNT if querying the geometry or mounting NVS fails.
 */
static el2go_ota_persist_status_t persist_init(void)
{
    struct flash_pages_info info = { 0 };
    int rc = -1;

    if (s_ready) {
        return EL2GO_OTA_PERSIST_OK;
    }

    s_nvs.flash_device = PARTITION_DEVICE(agent_state_partition);
    if (!device_is_ready(s_nvs.flash_device)) {
        LOG_ERR("agent_state_partition flash device not ready");
        return EL2GO_OTA_PERSIST_ERR_NOT_READY;
    }

    s_nvs.offset = (off_t)PARTITION_OFFSET(agent_state_partition);

    rc = flash_get_page_info_by_offs(s_nvs.flash_device, s_nvs.offset, &info);
    if (rc != 0) {
        LOG_ERR("flash_get_page_info_by_offs failed: %d", rc);
        return EL2GO_OTA_PERSIST_ERR_MOUNT;
    }

    s_nvs.sector_size = (uint32_t)info.size;
    s_nvs.sector_count = (uint16_t)(PARTITION_SIZE(agent_state_partition) / s_nvs.sector_size);

    rc = nvs_mount(&s_nvs);
    if (rc != 0) {
        LOG_ERR("nvs_mount failed: %d", rc);
        return EL2GO_OTA_PERSIST_ERR_MOUNT;
    }

    s_ready = true;
    return EL2GO_OTA_PERSIST_OK;
}

/**
 * @brief Loads the persisted agent record from NVS
 *
 * Zephyr NVS backend variant of el2go_ota_persist_read(). Mounts NVS if
 * needed, then reads the record. When no record exists the output is zeroed
 * and its valid field is cleared, still reporting success.
 *
 * @param[out] out Record to populate. Must not be NULL
 *
 * @retval EL2GO_OTA_PERSIST_OK on success or when no record is stored.
 * @retval EL2GO_OTA_PERSIST_ERR_ARG if out is NULL.
 * @retval EL2GO_OTA_PERSIST_ERR_NOT_READY if the storage device is not ready.
 * @retval EL2GO_OTA_PERSIST_ERR_MOUNT if the storage cannot be mounted.
 * @retval EL2GO_OTA_PERSIST_ERR_IO if the read fails.
 */
el2go_ota_persist_status_t el2go_ota_persist_read(agent_persist_t *out)
{
    el2go_ota_persist_status_t status = EL2GO_OTA_PERSIST_OK;
    ssize_t rc = -1;

    if (out == NULL) {
        return EL2GO_OTA_PERSIST_ERR_ARG;
    }

    status = persist_init();
    if (status != EL2GO_OTA_PERSIST_OK) {
        return status;
    }

    rc = nvs_read(&s_nvs, AGENT_PERSIST_NVS_KEY, out, sizeof(*out));

    if (rc == -ENOENT) {
        memset(out, 0, sizeof(*out));
        out->valid = 0U;
        return EL2GO_OTA_PERSIST_OK;
    }
    if (rc < 0) {
        LOG_ERR("nvs_read failed: %d", (int)rc);
        return EL2GO_OTA_PERSIST_ERR_IO;
    }

    return EL2GO_OTA_PERSIST_OK;
}

/**
 * @brief Saves the agent record to NVS
 *
 * Zephyr NVS backend variant of el2go_ota_persist_write(). Mounts NVS if needed
 * and writes the record under AGENT_PERSIST_NVS_KEY.
 *
 * @param[in] in Record to store. Must not be NULL
 *
 * @retval EL2GO_OTA_PERSIST_OK on success.
 * @retval EL2GO_OTA_PERSIST_ERR_ARG if in is NULL.
 * @retval EL2GO_OTA_PERSIST_ERR_NOT_READY if the storage device is not ready.
 * @retval EL2GO_OTA_PERSIST_ERR_MOUNT if the storage cannot be mounted.
 * @retval EL2GO_OTA_PERSIST_ERR_IO if the write fails.
 * @retval EL2GO_OTA_PERSIST_ERR_PARTIAL if fewer bytes than requested were stored.
 */
el2go_ota_persist_status_t el2go_ota_persist_write(const agent_persist_t *in)
{
    el2go_ota_persist_status_t status = EL2GO_OTA_PERSIST_OK;
    ssize_t rc = -1;

    if (in == NULL) {
        return EL2GO_OTA_PERSIST_ERR_ARG;
    }

    status = persist_init();
    if (status != EL2GO_OTA_PERSIST_OK) {
        return status;
    }

    rc = nvs_write(&s_nvs, AGENT_PERSIST_NVS_KEY, in, sizeof(*in));

    if (rc < 0) {
        LOG_ERR("nvs_write failed: %d", (int)rc);
        return EL2GO_OTA_PERSIST_ERR_IO;
    }

    if (rc > 0 && rc != (ssize_t)sizeof(*in)) {
        LOG_ERR("nvs_write partial write: %d of %zu", (int)rc, sizeof(*in));
        return EL2GO_OTA_PERSIST_ERR_PARTIAL;
    }

    return EL2GO_OTA_PERSIST_OK;
}

/**
 * @brief Clears the persisted agent record from NVS
 *
 * Zephyr NVS backend variant of el2go_ota_persist_clear(). Mounts NVS if
 * needed and deletes the record. Treats an already-absent record as success.
 *
 * @retval EL2GO_OTA_PERSIST_OK on success or if no record was present.
 * @retval EL2GO_OTA_PERSIST_ERR_NOT_READY if the storage device is not ready.
 * @retval EL2GO_OTA_PERSIST_ERR_MOUNT if the storage cannot be mounted.
 * @retval EL2GO_OTA_PERSIST_ERR_IO if the delete fails.
 */
el2go_ota_persist_status_t el2go_ota_persist_clear(void)
{
    el2go_ota_persist_status_t status = EL2GO_OTA_PERSIST_OK;
    int rc = -1;

    status = persist_init();
    if (status != EL2GO_OTA_PERSIST_OK) {
        return status;
    }

    rc = nvs_delete(&s_nvs, AGENT_PERSIST_NVS_KEY);

    if (rc < 0 && rc != -ENOENT) {
        LOG_ERR("nvs_delete failed: %d", rc);
        return EL2GO_OTA_PERSIST_ERR_IO;
    }

    return EL2GO_OTA_PERSIST_OK;
}
