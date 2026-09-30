/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include "el2go_blob_test_platform.h"

void el2go_blob_test_platform_init(void)
{
    /* No-op: Zephyr initializes hardware before main(). */
}

int64_t el2go_blob_test_uptime_ms(void)
{
    return k_uptime_get();
}

int64_t el2go_blob_test_uptime_delta(int64_t *reftime)
{
    return k_uptime_delta(reftime);
}
