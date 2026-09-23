/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef EL2GO_ZTEST_BRIDGE_H
#define EL2GO_ZTEST_BRIDGE_H

/** @defgroup el2go_ztest_bridge EL2GO Unit Test Ztest Bridge
 * @brief Ztest compatibility bridge shared by the EL2GO Zephyr unit test
 *        apps (el2go_ota_unit, el2go_fwual_unit).
 * @{
 */

/**
 * @brief Run one framework test suite through init -> register -> run.
 *
 * @param[in] reg  Suite registration function (e.g. register_fwual_public_tests).
 *                 Must not be NULL.
 * @return 0 if every test in the suite passed, non-zero otherwise.
 */
int el2go_run_suite(void (*reg)(void));

/** @} */ /* end of el2go_ztest_bridge */

#endif /* EL2GO_ZTEST_BRIDGE_H */
