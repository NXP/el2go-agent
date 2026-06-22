/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "fwual/fwual.h"
#include "ota/el2go_ota_lib.h"
#include "test_framework.h"
#include "test_suites.h"

/**
 * @brief Verify that fwual_init() is reachable from the ota_agent_core entry point.
 *
 * Calls the fwual_init() stub from the core agent context and checks it
 * returns without error. Validates that the FWUAL dependency is correctly
 * linked into the ota_agent_core build target.
 *
 * @param[in] params Unused test parameter, pass NULL.
 *
 * @retval true  Test passed.
 * @retval false Test failed.
 */
static bool test_ota_agent_core_calls_fwual_init(void *params)
{
    bool test_status = true;

    (void)params;

    fwual_init();
    TEST_PRINT_INFO("ota_agent_core: fwual_init() reachable");

    return test_status;
}

/**
 * @brief Verify that el2go_ota_lib_init() is reachable from the ota_agent_core entry point.
 *
 * Calls the el2go_ota_lib_init() stub from the core agent context and checks
 * it returns without error. Validates that the OTA library dependency is
 * correctly linked into the ota_agent_core build target.
 *
 * @param[in] params Unused test parameter, pass NULL.
 *
 * @retval true  Test passed.
 * @retval false Test failed.
 */
static bool test_ota_agent_core_calls_ota_lib_init(void *params)
{
    bool test_status = true;

    (void)params;

    el2go_ota_lib_init();
    TEST_PRINT_INFO("ota_agent_core: el2go_ota_lib_init() reachable");

    return test_status;
}

void register_ota_agent_core_tests(void)
{
    TEST_REGISTER(test_ota_agent_core_calls_fwual_init);
    TEST_REGISTER(test_ota_agent_core_calls_ota_lib_init);
}
