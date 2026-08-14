/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "el2go_ota_net.h"

/* Weak default implementation - does nothing. Overridden by backend-specific
 * implementations (e.g. zephyr/wifi/wifi.c) when a network backend is selected.
 */
__attribute__((weak)) int el2go_ota_net_init(void)
{
    return 0;
}
