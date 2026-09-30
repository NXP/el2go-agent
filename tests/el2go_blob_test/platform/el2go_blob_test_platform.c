/*
 * Copyright 2026 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

#include <psa/crypto_values.h>

#include "compiler.h"
#include "el2go_blob_test_platform.h"

__weak void el2go_blob_test_platform_init(void)
{
}

__weak int64_t el2go_blob_test_uptime_ms(void)
{
    return 0;
}

__weak int64_t el2go_blob_test_uptime_delta(int64_t *reftime)
{
    (void)reftime;
    return 0;
}

__weak psa_status_t el2go_blob_test_secure_storage_init(void)
{
    return PSA_SUCCESS;
}
