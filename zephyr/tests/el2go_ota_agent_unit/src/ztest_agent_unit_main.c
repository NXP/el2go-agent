/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <zephyr/ztest.h>

#include "test_suites.h"
#include "ztest_bridge.h"
#include "el2go_ota_lib_mock.h"
#include "fwual/fwual.h"
#include "wrap_app_sys.h"
#include "scheduler.h"
#include "el2go_ota_persist.h"

static void agent_unit_before(void *fixture)
{
    ARG_UNUSED(fixture);

    el2go_ota_lib_mock_reset();

    /* Reset the fake clock before scheduler_configure(), which reads
     * el2go_app_sys_uptime_ms() to arm the next target. */
    wrap_app_sys_reset();
    scheduler_configure(NULL, NULL);
    scheduler_reset();

    (void)fwual_init();
    (void)el2go_ota_persist_clear();
}

ZTEST_SUITE(el2go_agent_unit, NULL, NULL, agent_unit_before, NULL, NULL);

ZTEST(el2go_agent_unit, test_ota_agent_core_public)
{
    zassert_ok(el2go_run_suite(register_ota_agent_core_tests),
               "core agent public unit suite reported failures");
}

ZTEST(el2go_agent_unit, test_ota_agent_core_internal)
{
    zassert_ok(el2go_run_suite(register_ota_agent_core_internal_tests),
               "core agent internal unit suite reported failures");
}

ZTEST(el2go_agent_unit, test_ota_agent_advanced_public)
{
    zassert_ok(el2go_run_suite(register_ota_agent_advanced_tests),
               "advanced agent public unit suite reported failures");
}

ZTEST(el2go_agent_unit, test_ota_agent_advanced_internal)
{
    zassert_ok(el2go_run_suite(register_ota_agent_advanced_internal_tests),
               "advanced agent internal unit suite reported failures");
}
