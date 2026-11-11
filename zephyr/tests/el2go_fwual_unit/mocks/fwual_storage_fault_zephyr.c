/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "fwual_storage_fault.h"
#include "fwual_storage_mocks.h"
#include "fwual_state.h"

void fwual_storage_fault_reset(void)
{
    fwual_fake_reset();
}

bool fwual_storage_fault_supported(fwual_storage_fault_t fault)
{
    switch (fault) {
    case FWUAL_STORAGE_FAULT_STAGE_ERASE:
    case FWUAL_STORAGE_FAULT_STAGE_WRITE:
    case FWUAL_STORAGE_FAULT_STATE_PERSIST:
    case FWUAL_STORAGE_FAULT_BANK_ERASE:
    case FWUAL_STORAGE_FAULT_SLOT_OPEN:
    case FWUAL_STORAGE_FAULT_SLOT_READ:
    case FWUAL_STORAGE_FAULT_NVS_MOUNT:
    case FWUAL_STORAGE_FAULT_NVS_READ_STATE:
    case FWUAL_STORAGE_FAULT_NVS_READ_LIFECYCLE:
    case FWUAL_STORAGE_FAULT_NVS_WRITE_STATE:
    case FWUAL_STORAGE_FAULT_NVS_WRITE_PROGRESS:
    case FWUAL_STORAGE_FAULT_NVS_WRITE_LIFECYCLE:
    case FWUAL_STORAGE_FAULT_NVS_WRITE_SHORT:
    case FWUAL_STORAGE_FAULT_BOOT_REQUEST:
    case FWUAL_STORAGE_FAULT_BOOT_CONFIRM:
    case FWUAL_STORAGE_FAULT_BOOT_HEADER:
        return true;
    case FWUAL_STORAGE_FAULT_NONE:
    default:
        return false;
    }
}

bool fwual_storage_fault_arm(fwual_storage_fault_t fault)
{
    switch (fault) {
    case FWUAL_STORAGE_FAULT_STAGE_ERASE:
        fwual_fake_fail_next_erase(true);
        return true;
    case FWUAL_STORAGE_FAULT_STAGE_WRITE:
        fwual_fake_fail_next_write(true);
        return true;
    case FWUAL_STORAGE_FAULT_STATE_PERSIST:
        fwual_fake_fail_next_nvs_write(true);
        return true;
    case FWUAL_STORAGE_FAULT_BANK_ERASE:
        fwual_fake_fail_next_boot_erase(true);
        return true;
    case FWUAL_STORAGE_FAULT_SLOT_OPEN:
        fwual_fake_fail_next_open(true);
        return true;
    case FWUAL_STORAGE_FAULT_SLOT_READ:
        fwual_fake_fail_next_read(true);
        return true;
    case FWUAL_STORAGE_FAULT_NVS_MOUNT:
        fwual_fake_fail_nvs_mount(true);
        return true;
    case FWUAL_STORAGE_FAULT_NVS_READ_STATE:
        fwual_fake_fail_next_nvs_read_key((uint16_t)FWUAL_NVS_KEY_STATE);
        return true;
    case FWUAL_STORAGE_FAULT_NVS_READ_LIFECYCLE:
        fwual_fake_fail_next_nvs_read_key((uint16_t)FWUAL_NVS_KEY_LIFECYCLE);
        return true;
    case FWUAL_STORAGE_FAULT_NVS_WRITE_STATE:
        fwual_fake_fail_next_nvs_write_key((uint16_t)FWUAL_NVS_KEY_STATE);
        return true;
    case FWUAL_STORAGE_FAULT_NVS_WRITE_PROGRESS:
        fwual_fake_fail_next_nvs_write_key((uint16_t)FWUAL_NVS_KEY_WRITE_PROGRESS);
        return true;
    case FWUAL_STORAGE_FAULT_NVS_WRITE_LIFECYCLE:
        fwual_fake_fail_next_nvs_write_key((uint16_t)FWUAL_NVS_KEY_LIFECYCLE);
        return true;
    case FWUAL_STORAGE_FAULT_NVS_WRITE_SHORT:
        fwual_fake_short_next_nvs_write(true);
        return true;
    case FWUAL_STORAGE_FAULT_BOOT_REQUEST:
        fwual_fake_fail_next_boot_request(true);
        return true;
    case FWUAL_STORAGE_FAULT_BOOT_CONFIRM:
        fwual_fake_fail_next_boot_confirm(true);
        return true;
    case FWUAL_STORAGE_FAULT_BOOT_HEADER:
        fwual_fake_fail_next_boot_header(true);
        return true;
    case FWUAL_STORAGE_FAULT_NONE:
    default:
        return false;
    }
}

bool fwual_storage_fault_set_write_align(uint32_t align)
{
    fwual_fake_set_align(align);
    return true;
}

bool fwual_storage_fault_boot_upgrade_pending(void)
{
    return fwual_fake_boot_pending();
}

bool fwual_storage_fault_seed_nvs(uint16_t key, const void *data, size_t len)
{
    return fwual_fake_nvs_seed(key, data, len);
}

bool fwual_storage_fault_pending(void)
{
    return fwual_fake_fault_pending();
}
