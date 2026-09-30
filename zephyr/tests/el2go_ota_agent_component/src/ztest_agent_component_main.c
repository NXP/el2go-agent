/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <zephyr/ztest.h>

#include "test_ztest.h"

#include "test_el2go_ota_agent_core_internal.h"
#include "test_el2go_ota_agent_core_public.h"
#include "test_el2go_ota_agent_advanced_internal.h"
#include "test_el2go_ota_agent_advanced_public.h"

ZTEST_SUITE(el2go_agent_ct, NULL, NULL, NULL, NULL, NULL);

TEST_ZTEST_SUITE(el2go_agent_ct, ota_agent_core_internal)
TEST_ZTEST_SUITE(el2go_agent_ct, ota_agent_core_public)
TEST_ZTEST_SUITE(el2go_agent_ct, ota_agent_advanced_internal)
TEST_ZTEST_SUITE(el2go_agent_ct, ota_agent_advanced_public)
