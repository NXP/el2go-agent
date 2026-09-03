/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "test_el2go_ota_agent_advanced_internal.h"

/* Pending placeholder: no advanced-agent internal body implemented yet. */
static test_result_t test_aa_internal_pending(void)
{
    TEST_SKIP_WITH("advanced-agent internal component tests not implemented yet");
}

TEST_SUITE_BEGIN(ota_agent_advanced_internal)
TEST_REGISTER("-", test_aa_internal_pending)
TEST_SUITE_END(ota_agent_advanced_internal)
