/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef __TEST_SUITES_H__
#define __TEST_SUITES_H__

#include <stdbool.h>

/**
 * @defgroup test_suites Test Suites
 * @brief Registration interface for all unit test suites.
 *
 * Each function registers the tests for a specific module.
 * Different implementations exist depending on whether the build
 * targets the public or internal API.
 * @{
 */

/**
 * @brief Register all EL2GO RTP tests.
 */
void register_el2go_rtp_tests(bool include_fs_tests);

/**
 * @brief Register all datastore tests.
 */
void register_datastore_tests(void);

/**
 * @brief Register all FWUAL library tests.
 */
void register_fwual_tests(void);

/**
 * @brief Register all EL2GO OTA Library tests.
 */
void register_ota_lib_tests(void);

/**
 * @brief Register all internal EL2GO OTA Library tests.
 */
void register_ota_lib_internal_tests(void);

/**
 * @brief Register all el2go_ota_agent_core tests.
 */
void register_ota_agent_core_tests(void);

/**
 * @brief Register all el2go_ota_agent_advanced tests.
 */
void register_ota_agent_advanced_tests(void);

/**
 * @brief Register all net_crypto tests.
 */
void register_net_crypto_tests(void);

/**
 * @brief Register all keystore tests.
 */
void register_keystore_tests(void);

/** @} */ /* end of test_suites */

#endif /* __TEST_SUITES_H__ */
