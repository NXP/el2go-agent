/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
*/

#include "el2go_csr_platform.h"
#include "el2go_csr_console.h"
#include "el2go_csr_bsp.h"

platform_status_t platform_init(void)
{
    BOARD_InitHardware();

    LOG(LOG_TRACE, "Platform (FRDMKW43) has been initialized successfully. \r\n");
    return kStatus_PLATFORM_INIT_SUCCESS;
}