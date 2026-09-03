/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <zephyr/ztest.h>

#include "test_ztest.h"

#include "test_el2go_ota_lib_internal.h"
#include "test_el2go_ota_lib_public.h"
#include "test_fwual_internal.h"
#include "test_fwual_public.h"
#include "test_el2go_ota_agent_core_internal.h"
#include "test_el2go_ota_agent_core_public.h"
#include "test_el2go_ota_agent_advanced_internal.h"
#include "test_el2go_ota_agent_advanced_public.h"

ZTEST_SUITE(el2go_ct, NULL, NULL, NULL, NULL, NULL);

TEST_ZTEST_SUITE(el2go_ct, ota_lib_internal)
TEST_ZTEST_SUITE(el2go_ct, ota_lib_public)
TEST_ZTEST_SUITE(el2go_ct, fwual_internal)
TEST_ZTEST_SUITE(el2go_ct, fwual_public)

TEST_ZTEST_SUITE(el2go_ct, ota_agent_core_internal)
TEST_ZTEST_SUITE(el2go_ct, ota_agent_core_public)
TEST_ZTEST_SUITE(el2go_ct, ota_agent_advanced_internal)
TEST_ZTEST_SUITE(el2go_ct, ota_agent_advanced_public)
