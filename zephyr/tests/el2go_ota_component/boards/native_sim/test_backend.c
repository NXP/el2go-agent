/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "test_framework.h"

uint32_t ct_backend_caps(void)
{
    /* FWUAL is mocked here; see el2go_fwual_component for the real backend. */
    return CT_CAP_MOCK_TRANSPORT | CT_CAP_REAL_FLASH;
}
