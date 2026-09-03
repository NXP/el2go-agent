/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "test_el2go_ota_agent_core_public.h"

/* Pending placeholder: no core-agent public body implemented yet. */
static test_result_t test_ac_public_pending(void)
{
    TEST_SKIP_WITH("core-agent public component tests not implemented yet");
}

/* ---- suite table ------------------------------------------------------- */

TEST_SUITE_BEGIN(ota_agent_core_public)
TEST_REGISTER("-", test_ac_public_pending)
TEST_SUITE_END(ota_agent_core_public)
