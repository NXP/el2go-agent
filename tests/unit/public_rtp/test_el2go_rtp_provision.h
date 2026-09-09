/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef TEST_EL2GO_RTP_PROVISION_H
#define TEST_EL2GO_RTP_PROVISION_H

/** @defgroup test_el2go_rtp_provision RTP Provisioning Unit Test
 * @brief Test suite for el2go_rtp_provision() public API.
 * @{
 */
#include <stdbool.h>

/**
 * @brief Register all el2go_rtp_provision() tests.
 *
 * @param include_fs_tests  If true, also register tests that require
 *                          filesystem datastore support.
 */
void register_el2go_rtp_provision_tests(bool include_fs_tests);

/** @} */ /* end of test_el2go_rtp_provision */

#endif /* TEST_EL2GO_RTP_PROVISION_H */