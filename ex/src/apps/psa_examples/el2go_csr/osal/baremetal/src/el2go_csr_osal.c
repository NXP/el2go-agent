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
    __asm__ volatile("nop");

    return kStatus_OS_INIT_SUCCESS;
}