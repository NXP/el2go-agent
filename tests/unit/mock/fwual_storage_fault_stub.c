/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "fwual_storage_fault.h"

void fwual_storage_fault_reset(void)
{
    /* No fake storage state to reset. */
}

bool fwual_storage_fault_supported(fwual_storage_fault_t fault)
{
    (void)fault;
    return false;
}

bool fwual_storage_fault_arm(fwual_storage_fault_t fault)
{
    (void)fault;
    return false;
}

bool fwual_storage_fault_set_write_align(uint32_t align)
{
    (void)align;
    return false;
}

bool fwual_storage_fault_boot_upgrade_pending(void)
{
    return false;
}

bool fwual_storage_fault_seed_nvs(uint16_t key, const void *data, size_t len)
{
    (void)key;
    (void)data;
    (void)len;
    return false;
}

bool fwual_storage_fault_pending(void)
{
    return false;
}
