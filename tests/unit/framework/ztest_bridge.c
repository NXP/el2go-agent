/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "ztest_bridge.h"

#include "test_framework.h"

int el2go_run_suite(void (*reg)(void))
{
    if (reg == NULL) {
        return -1;
    }

    test_framework_init();

    reg();
    return test_framework_run();
}
