/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef TEST_EL2GO_RTP_PROVISION_H
#define TEST_EL2GO_RTP_PROVISION_H

#include <stdbool.h>

/**
 * @brief Register all el2go_rtp_provision() tests.
 *
 * @param include_fs_tests  If true, also register tests that require
 *                          filesystem datastore support.
 */
void register_el2go_rtp_provision_tests(bool include_fs_tests);

#endif /* TEST_EL2GO_RTP_PROVISION_H */