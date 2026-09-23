/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "fwual_storage_fault.h"
#include "fwual_storage_mocks.h"

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
