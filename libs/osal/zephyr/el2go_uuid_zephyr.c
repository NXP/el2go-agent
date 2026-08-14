/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Zephyr-specific implementation of osal_uuid().
 * Reads the hardware device ID via the Zephyr hwinfo API and copies the raw
 * bytes into the caller-provided buffer.  No heap allocation is performed.
 */

#include <zephyr/kernel.h>
#include <zephyr/drivers/hwinfo.h>
#include <string.h>

#include "osal.h"
#include "debug.h"

/*
 * osal_uuid - Read the hardware device ID into a caller-provided buffer.
 *
 * Uses hwinfo_get_device_id() which is backed by CONFIG_HWINFO.
 * Returns EL2GO_STATUS_NOT_IMPLEMENTED when CONFIG_HWINFO is not enabled.
 * Returns EL2GO_STATUS_BUFFER_TOO_SMALL when buf_len is zero.
 */
el2go_status_t osal_uuid(uint8_t *buf, size_t buf_len, size_t *uuid_len)
{
    ssize_t ret = 0;

    if (!buf || buf_len == 0U || !uuid_len) {
        return EL2GO_STATUS_INVALID_PARAMETER;
    }

#if defined(CONFIG_HWINFO)
    ret = hwinfo_get_device_id(buf, buf_len);
    if (ret < 0) {
        EL2GO_DBG_PRINTF(ERROR, "hwinfo_get_device_id failed: %d\n", (int)ret);
        return EL2GO_STATUS_FAILURE;
    }

    *uuid_len = (size_t)ret;
    EL2GO_DBG_PRINTF(VERBOSE, "Device UUID read (%zu bytes)\n", *uuid_len);
    return EL2GO_STATUS_SUCCESS;
#else
    (void)buf;
    (void)buf_len;
    (void)uuid_len;
    EL2GO_DBG_PRINTF(ERROR, "CONFIG_HWINFO not enabled\n");
    return EL2GO_STATUS_NOT_IMPLEMENTED;
#endif
}
