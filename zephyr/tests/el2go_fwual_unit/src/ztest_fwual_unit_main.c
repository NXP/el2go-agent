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

static bool s_boot_suite_done;
static int s_boot_suite_rc;

/* Reset the RAM-backed flash/NVS/MCUboot fakes before every test case. */
static void fwual_unit_before(void *fixture)
{
    ARG_UNUSED(fixture);
    fwual_fake_reset();
}

ZTEST_SUITE(el2go_fwual_unit, NULL, NULL, fwual_unit_before, NULL, NULL);

/*
 * FWUAL keeps its state in statics and fwual_init() is idempotent once it has
 * succeeded. The boot-sequence suite exercises the init error paths and
 * therefore has to run before any other test has initialised the library.
 * Whichever test case ztest picks first runs it, so no test depends on the
 * ZTEST execution order.
 */
static void fwual_run_boot_suite_once(void)
{
    if (!s_boot_suite_done) {
        s_boot_suite_done = true;
        s_boot_suite_rc = el2go_run_suite(register_fwual_boot_tests);
    }
    zassert_ok(s_boot_suite_rc, "FWUAL boot-sequence unit suite reported failures");
}

ZTEST(el2go_fwual_unit, test_fwual_public)
{
    fwual_run_boot_suite_once();
    fwual_fake_reset();
    zassert_ok(el2go_run_suite(register_fwual_tests), "FWUAL public unit suite reported failures");
}

ZTEST(el2go_fwual_unit, test_fwual_internal)
{
    fwual_run_boot_suite_once();
    fwual_fake_reset();
    zassert_ok(el2go_run_suite(register_fwual_internal_tests),
               "FWUAL internal unit suite reported failures");
}

ZTEST(el2go_fwual_unit, test_fwual_errors)
{
    fwual_run_boot_suite_once();
    fwual_fake_reset();
    zassert_ok(el2go_run_suite(register_fwual_error_tests),
               "FWUAL error-path unit suite reported failures");
}
