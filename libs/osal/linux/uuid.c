/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "common/el2go_status.h"
#include "osal.h"

el2go_status_t osal_uuid(uint8_t *buf, size_t buf_len, size_t *uuid_len)
{
    (void)buf;
    (void)buf_len;
    (void)uuid_len;

    return EL2GO_STATUS_NOT_IMPLEMENTED;
}
