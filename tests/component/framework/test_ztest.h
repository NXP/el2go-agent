/*
 * Copyright 2018-2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef EL2GO_TEST_ZTEST_H
#define EL2GO_TEST_ZTEST_H

#include <zephyr/ztest.h>

#include "test_suite.h"

/**
 * @brief Run every case in a suite table and map the aggregate to a ztest result.
 *
 * @param cases Pointer to the suite's test_case_t array.
 * @param count Number of entries in @p cases.
 */

static inline void test_run_suite(const test_case_t *cases, size_t count)
{
    size_t passed = 0U;
    size_t skipped = 0U;
    size_t failed = 0U;
    size_t i;

    for (i = 0U; i < count; i++) {
        test_result_t r = cases[i].fn();

        switch (r) {
        case TEST_PASS:
            passed++;
            (void)printf("[CT] PASS %-22s %s\n", cases[i].plan_id, cases[i].name);
            break;
        case TEST_SKIP:
            skipped++;
            (void)printf("[CT] SKIP %-22s %s\n", cases[i].plan_id, cases[i].name);
            break;
        case TEST_FAIL:
        default:
            failed++;
            (void)printf("[CT] FAIL %-22s %s\n", cases[i].plan_id, cases[i].name);
            break;
        }
    }

    (void)printf("[CT] suite summary: %u passed, %u skipped, %u failed (of %u)\n", (unsigned)passed,
                 (unsigned)skipped, (unsigned)failed, (unsigned)count);

    if (failed != 0U) {
        zassert_equal(failed, 0U, "%u component case(s) failed", (unsigned)failed);
    } else if (passed == 0U && skipped != 0U) {
        ztest_test_skip();
    }
}

/**
 * @brief Define a ztest that runs an entire suite table.
 *
 * @param ztest_suite ztest suite identifier (the ZTEST_SUITE name).
 * @param suite       Portable suite name used in TEST_SUITE_DECLARE/BEGIN/END.
 */

#define TEST_ZTEST_SUITE(ztest_suite, suite)                 \
    ZTEST(ztest_suite, suite)                                \
    {                                                        \
        size_t _n = 0U;                                      \
        const test_case_t *_c = test_suite_get_##suite(&_n); \
        test_run_suite(_c, _n);                              \
    }

#endif /* EL2GO_TEST_ZTEST_H */
