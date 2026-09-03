/*
 * Copyright 2018-2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "test_el2go_ota_agent_advanced_public.h"

/* Pending placeholder: no advanced-agent public body implemented yet. */
static test_result_t test_aa_public_pending(void)
{
    TEST_SKIP_WITH("advanced-agent public component tests not implemented yet");
}

/* ---- suite table ------------------------------------------------------- */

TEST_SUITE_BEGIN(ota_agent_advanced_public)
TEST_REGISTER("-", test_aa_public_pending)
TEST_SUITE_END(ota_agent_advanced_public)
