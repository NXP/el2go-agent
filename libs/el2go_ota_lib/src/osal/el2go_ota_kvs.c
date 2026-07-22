/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "compiler.h"
#include "el2go_ota_kvs.h"

__weak el2go_ota_status_t el2go_ota_kvs_init(void)
{
    return EL2GO_OTA_SUCCESS;
}

__weak el2go_ota_status_t el2go_ota_kvs_write(uint16_t key, const void *data, size_t len)
{
    (void)key;
    (void)data;
    (void)len;
    return EL2GO_OTA_SUCCESS;
}

__weak el2go_ota_status_t el2go_ota_kvs_read(uint16_t key, void *data, size_t len, bool *found)
{
    (void)key;
    (void)data;
    (void)len;
    *found = false;
    return EL2GO_OTA_SUCCESS;
}

__weak el2go_ota_status_t el2go_ota_kvs_delete(uint16_t key)
{
    (void)key;
    return EL2GO_OTA_SUCCESS;
}
