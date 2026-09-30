/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef EL2GO_ZTEST_BRIDGE_H
#define EL2GO_ZTEST_BRIDGE_H

/** @defgroup el2go_ota_ztest_bridge OTA Unit Test Ztest Bridge
 * @brief Ztest compatibility bridge for EL2GO OTA unit tests.
 * @{
 */

/**
 * @brief Run one framework test suite through init -> register -> run.
 *
 * @param[in] reg  Suite registration function (e.g. register_fwual_tests).
 *                 Must not be NULL.
 * @return 0 if every test in the suite passed, non-zero otherwise.
 */
int el2go_run_suite(void (*reg)(void));

/** @} */ /* end of el2go_ota_ztest_bridge */

#endif /* EL2GO_ZTEST_BRIDGE_H */
