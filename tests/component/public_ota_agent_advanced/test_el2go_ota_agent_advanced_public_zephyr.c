/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "test_el2go_ota_agent_advanced_public_zephyr.h"

#include "agent_component_fixtures.h"

/* ---- suite table ------------------------------------------------------- */

TEST_SUITE_BEGIN(ota_agent_advanced_public)
TEST_REGISTER("OTA_CT_AA_0.1", agent_ct_public_api_reachable)
TEST_SUITE_END(ota_agent_advanced_public)
