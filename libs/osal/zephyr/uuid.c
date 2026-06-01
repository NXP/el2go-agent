/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <zephyr/drivers/hwinfo.h>
#include "common/el2go_status.h"
#include "osal.h"

#define DEVICE_UUID_LEN 16U

el2go_status_t osal_uuid(uint8_t **uuid, size_t *uuid_len)
{
    uint8_t *buf = NULL;
    ssize_t ret = 0;

    if (!uuid || !uuid_len)
        return EL2GO_STATUS_INVALID_POINTER;

    buf = (uint8_t *)osal_malloc(DEVICE_UUID_LEN);
    if (!buf)
        return EL2GO_STATUS_ALLOCATION_ERROR;

    ret = hwinfo_get_device_id(buf, DEVICE_UUID_LEN);
    if (ret <= 0) {
        osal_free(buf);
        return EL2GO_STATUS_FAILURE;
    }

    *uuid = buf;
    *uuid_len = (size_t)ret;

    return EL2GO_STATUS_SUCCESS;
}
