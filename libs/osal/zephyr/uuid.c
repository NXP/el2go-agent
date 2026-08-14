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

el2go_status_t osal_uuid(uint8_t *buf, size_t buf_len, size_t *uuid_len)
{
    ssize_t ret = 0;

    if (!buf || !uuid_len)
        return EL2GO_STATUS_INVALID_POINTER;

    if (buf_len < DEVICE_UUID_LEN)
        return EL2GO_STATUS_BUFFER_TOO_SMALL;

    ret = hwinfo_get_device_id(buf, DEVICE_UUID_LEN);
    if (ret <= 0)
        return EL2GO_STATUS_FAILURE;

    *uuid_len = (size_t)ret;

    return EL2GO_STATUS_SUCCESS;
}
