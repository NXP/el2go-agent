/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <errno.h>
#include <string.h>

#include <zephyr/device.h>

#include <zephyr/devicetree.h>
#include <zephyr/drivers/flash.h>
#include <zephyr/drivers/flash/flash_simulator.h>

static const struct device *const s_flash_dev = DEVICE_DT_GET(DT_CHOSEN(zephyr_flash_controller));

/** Byte range of slot1_partition (secondary/inactive image slot) within the
 * sim-flash address space -- this is where FWUAL actually writes new images. */
#define FAULT_RANGE_BASE 0x00075000UL
#define FAULT_RANGE_SIZE 0x00069000UL

/** Byte range of storage_partition (NVS) within the sim-flash address space. */
#define NVS_FAULT_RANGE_BASE 0x000fc000UL
#define NVS_FAULT_RANGE_SIZE 0x00004000UL

/** Selects which range is currently active; only one may be armed at a time. */
static bool s_nvs_fault_armed;

/** Number of bytes in the image slot range that may still be written before faulting. */
static uint32_t s_slot_bytes_allowed;

static bool offset_in_fault_range(off_t offset)
{
    return ((uint32_t)offset >= FAULT_RANGE_BASE) &&
           ((uint32_t)offset < (FAULT_RANGE_BASE + FAULT_RANGE_SIZE));
}

static bool offset_in_nvs_fault_range(off_t offset)
{
    return ((uint32_t)offset >= NVS_FAULT_RANGE_BASE) &&
           ((uint32_t)offset < (NVS_FAULT_RANGE_BASE + NVS_FAULT_RANGE_SIZE));
}

static int fault_write_byte_cb(const struct device *dev, off_t offset, uint8_t data)
{
    bool in_range = s_nvs_fault_armed ? offset_in_nvs_fault_range(offset) :
                                        offset_in_fault_range(offset);

    if (in_range && !s_nvs_fault_armed && s_slot_bytes_allowed > 0U) {
        s_slot_bytes_allowed--;
        return (int)data;
    }
    if (in_range) {
        return -EIO;
    }
    (void)dev;
    return (int)data;
}

static int fault_erase_unit_cb(const struct device *dev, off_t unit_offset)
{
    bool in_range = s_nvs_fault_armed ? offset_in_nvs_fault_range(unit_offset) :
                                        offset_in_fault_range(unit_offset);

    if (in_range) {
        return -EIO;
    }

    /* Outside the fault range: perform the normal erase ourselves, since
     * installing a callback disables the simulator's built-in erase. */
    {
        size_t flash_size = 0U;
        uint8_t *flash_mock = flash_simulator_get_memory(dev, &flash_size);
        const struct flash_simulator_params *params = flash_simulator_get_params(dev);

        if (flash_mock == NULL || params == NULL ||
            (size_t)unit_offset + params->erase_unit > flash_size) {
            return -EIO;
        }
        memset(flash_mock + unit_offset, params->erase_value, params->erase_unit);
    }
    return 0;
}

static const struct flash_simulator_cb s_fault_cbs = {
    .write_byte = fault_write_byte_cb,
    .erase_unit = fault_erase_unit_cb,
};

bool ct_fw_flash_fault_arm(bool arm)
{
    if (!device_is_ready(s_flash_dev)) {
        return false;
    }

    s_nvs_fault_armed = false;
    s_slot_bytes_allowed = 0U;
    flash_simulator_set_callbacks(s_flash_dev, arm ? &s_fault_cbs : NULL);
    return true;
}

bool ct_fw_flash_fault_arm_after(uint32_t bytes_allowed)
{
    if (!device_is_ready(s_flash_dev)) {
        return false;
    }

    s_nvs_fault_armed = false;
    s_slot_bytes_allowed = bytes_allowed;
    flash_simulator_set_callbacks(s_flash_dev, &s_fault_cbs);
    return true;
}

bool ct_fw_flash_fault_arm_nvs(bool arm)
{
    if (!device_is_ready(s_flash_dev)) {
        return false;
    }

    s_nvs_fault_armed = arm;
    flash_simulator_set_callbacks(s_flash_dev, arm ? &s_fault_cbs : NULL);
    return true;
}
