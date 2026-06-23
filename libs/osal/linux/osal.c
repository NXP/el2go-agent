/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "osal.h"
#include "local.h"

void osal_lib_init(void)
{
    set_log_file();
    set_log_level();
}
