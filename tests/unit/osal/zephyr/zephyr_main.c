/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <zephyr/ztest.h>
#include "test_framework.h"
#include "test_suites.h"

ZTEST_SUITE(el2go_ota_tests, NULL, NULL, NULL, NULL, NULL);

ZTEST(el2go_ota_tests, test_run_all_ota_suites)
{
    test_framework_init();
    register_fwual_tests();
    register_ota_lib_tests();
    register_ota_agent_core_tests();
    register_ota_agent_advanced_tests();
    int result = test_framework_run();
    zassert_equal(0, result, "OTA unit tests failed: %d test(s) failed", result);
}
