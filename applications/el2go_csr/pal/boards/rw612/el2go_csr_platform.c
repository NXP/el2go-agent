/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "el2go_csr_platform.h"
#include "el2go_csr_console.h"

platform_status_t platform_init(void)
{
    /* On Zephyr the kernel already initialised the hardware before main()
     * is called.  SECURE_STORAGE (PSA ITS via ZMS) is auto-initialised by
     * the Zephyr subsystem; no explicit call to secure_storage_its_initialize()
     * is needed here.
     */
    LOG(LOG_TRACE, "Platform (RW612 Zephyr) has been initialised successfully.\r\n");
    return kStatus_PLATFORM_INIT_SUCCESS;
}
