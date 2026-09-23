/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <zephyr/ztest.h>

#include "test_suites.h"
#include "fwual_storage_mocks.h"
#include "ztest_bridge.h"

void register_fwual_internal_tests(void);

/* Reset the RAM-backed flash/NVS/MCUboot fakes before every test case. */
static void fwual_unit_before(void *fixture)
{
    ARG_UNUSED(fixture);
    fwual_fake_reset();
}

ZTEST_SUITE(el2go_fwual_unit, NULL, NULL, fwual_unit_before, NULL, NULL);

ZTEST(el2go_fwual_unit, test_fwual_public)
{
    zassert_ok(el2go_run_suite(register_fwual_tests), "FWUAL public unit suite reported failures");
}

ZTEST(el2go_fwual_unit, test_fwual_internal)
{
    zassert_ok(el2go_run_suite(register_fwual_internal_tests),
               "FWUAL internal unit suite reported failures");
}
