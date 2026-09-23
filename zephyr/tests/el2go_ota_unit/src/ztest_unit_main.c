/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <zephyr/ztest.h>

#include "test_suites.h"
#include "ztest_bridge.h"

ZTEST_SUITE(el2go_ota_unit, NULL, NULL, NULL, NULL, NULL);

ZTEST(el2go_ota_unit, test_ota_lib_public)
{
    zassert_ok(el2go_run_suite(register_ota_lib_tests),
               "OTA lib public unit suite reported failures");
}

ZTEST(el2go_ota_unit, test_ota_lib_internal)
{
    zassert_ok(el2go_run_suite(register_ota_lib_internal_tests),
               "OTA lib internal unit suite reported failures");
}

ZTEST(el2go_ota_unit, test_ota_agent_core)
{
    zassert_ok(el2go_run_suite(register_ota_agent_core_tests),
               "OTA agent core unit suite reported failures");
}

ZTEST(el2go_ota_unit, test_ota_agent_advanced)
{
    zassert_ok(el2go_run_suite(register_ota_agent_advanced_tests),
               "OTA agent advanced unit suite reported failures");
}
