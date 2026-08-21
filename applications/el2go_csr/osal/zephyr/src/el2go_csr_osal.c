/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
*/

#include "el2go_csr_osal.h"
#include "el2go_csr_osal_types.h"

os_status_t os_init(void)
{
    /* Zephyr kernel is already running when main() is called. */
    /* No additional OS initialisation is required here.       */
    return kStatus_OS_INIT_SUCCESS;
}
