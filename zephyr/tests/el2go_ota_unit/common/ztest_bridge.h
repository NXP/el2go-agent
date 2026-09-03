/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef EL2GO_ZTEST_BRIDGE_H
#define EL2GO_ZTEST_BRIDGE_H

/**
 * @brief Run one framework test suite through init -> register -> run.
 *
 * @param[in] reg  Suite registration function (e.g. register_fwual_tests).
 *                 Must not be NULL.
 * @return 0 if every test in the suite passed, non-zero otherwise.
 */
int el2go_run_suite(void (*reg)(void));

#endif /* EL2GO_ZTEST_BRIDGE_H */
