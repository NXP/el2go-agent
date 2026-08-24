/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <zephyr/kernel.h>
#include <zephyr/drivers/hwinfo.h>
#include <string.h>

#include "osal.h"
#include "debug.h"

/*
 * osal_uuid - Read the hardware device ID into a caller-provided buffer.
 *
 * Uses hwinfo_get_device_id() which is backed by HWINFO (selected by
 * EL2GO_RTP_AGENT in Kconfig). Builds without EL2GO_RTP_AGENT will
 * not compile this file.
 */
el2go_status_t osal_uuid(uint8_t *buf, size_t buf_len, size_t *uuid_len)
{
    ssize_t ret = 0;

    if (!buf || buf_len == 0U || !uuid_len) {
        return EL2GO_STATUS_INVALID_PARAMETER;
    }

    ret = hwinfo_get_device_id(buf, buf_len);
    if (ret < 0) {
        EL2GO_DBG_PRINTF(ERROR, "hwinfo_get_device_id failed: %d\n", (int)ret);
        return EL2GO_STATUS_FAILURE;
    }

    *uuid_len = (size_t)ret;
    EL2GO_DBG_PRINTF(VERBOSE, "Device UUID read (%zu bytes)\n", *uuid_len);
    return EL2GO_STATUS_SUCCESS;
}
