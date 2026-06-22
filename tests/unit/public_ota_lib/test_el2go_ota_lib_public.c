/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "ota/el2go_ota_lib.h"
#include "test_framework.h"
#include "test_suites.h"

/**
 * @brief Verify that el2go_ota_lib_init() can be called without crashing.
 *
 * Calls the el2go_ota_lib_init() stub and checks it returns without error.
 * Validates that the build system correctly wires the OTA library public API
 * and that the stub implementation is reachable at link time.
 *
 * @param[in] params Unused test parameter, pass NULL.
 *
 * @retval true  Test passed.
 * @retval false Test failed.
 */
static bool test_el2go_ota_lib_init_does_not_crash(void *params)
{
    bool test_status = true;

    (void)params;

    el2go_ota_lib_init();
    TEST_PRINT_INFO("el2go_ota_lib_init() stub called successfully");

    return test_status;
}

void register_ota_lib_tests(void)
{
    TEST_REGISTER(test_el2go_ota_lib_init_does_not_crash);
}
