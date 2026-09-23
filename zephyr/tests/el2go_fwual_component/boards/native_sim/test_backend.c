/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "test_framework.h"

uint32_t ct_backend_caps(void)
{
    return CT_CAP_REAL_FLASH | CT_CAP_MCUBOOT | CT_CAP_FLASH_FAULT;
}
