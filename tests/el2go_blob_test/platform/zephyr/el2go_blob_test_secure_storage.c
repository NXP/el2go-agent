/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "secure_storage.h"
#include "el2go_blob_test_platform.h"

psa_status_t el2go_blob_test_secure_storage_init(void)
{
    psa_status_t psa_status = secure_storage_its_initialize();
    if (psa_status != PSA_SUCCESS) {
        LOG("secure_storage_its_initialize failed!\r\n");
    }
    return psa_status;
}
