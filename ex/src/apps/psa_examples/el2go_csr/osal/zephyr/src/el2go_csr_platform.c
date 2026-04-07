/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
*/

#include "platform_init.h"

void platform_init(void)
{
    // No additional initialization required for Zephyr platform
    // Zephyr kernel handles hardware initialization automatically
    
    __asm__ volatile("nop");
}