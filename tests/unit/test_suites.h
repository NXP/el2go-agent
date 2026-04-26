/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright 2026 NXP
 */

#ifndef __TEST_SUITES_H__
#define __TEST_SUITES_H__
/**
 * Register test suites
 *
 * Each function registers tests for a specific suite.
 * Different implementations exist for public vs internal builds.
 */
void register_el2go_rtp_tests(void);
void register_datastore_tests(void);

#endif /* __TEST_SUITES_H__ */
