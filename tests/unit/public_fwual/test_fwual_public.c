/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "fwual/fwual.h"
#include "test_framework.h"
#include "test_suites.h"

/**
 * @brief Verify that fwual_init() can be called without crashing.
 *
 * Calls the fwual_init() stub and checks it returns without error.
 * Validates that the build system correctly wires the FWUAL public API
 * and that the stub implementation is reachable at link time.
 *
 * @param[in] params Unused test parameter, pass NULL.
 *
 * @retval true  Test passed.
 * @retval false Test failed.
 */
static bool test_fwual_init_does_not_crash(void *params)
{
    bool test_status = true;

    (void)params;

    fwual_init();
    TEST_PRINT_INFO("fwual_init() stub called successfully");

    return test_status;
}

void register_fwual_tests(void)
{
    TEST_REGISTER(test_fwual_init_does_not_crash);
}
