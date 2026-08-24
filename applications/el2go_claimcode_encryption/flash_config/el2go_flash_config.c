/*
 * Copyright 2026 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "el2go_flash_config.h"

/*
 * Default (weak) implementation: the device is executing from XIP flash, so
 * the FCB is already programmed and can be read directly from flash.
 */
__attribute__((weak)) void el2go_flash_get_config(flexspi_nor_config_t *config,
                                                  uint32_t fcb_address)
{
    *config = *((flexspi_nor_config_t *)fcb_address);
}
