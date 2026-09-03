/*
 * Copyright 2018-2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef EL2GO_TEST_SUITE_H
#define EL2GO_TEST_SUITE_H

#include "test_framework.h"

/** A single portable component test case. */
typedef struct {
    const char *plan_id;       /**< Exact test-plan ID, or "-" if none. */
    const char *name;          /**< Short ztest-friendly name (unique per suite). */
    test_result_t (*fn)(void); /**< The portable test body. */
} test_case_t;

/**
 * @brief Declare the getter/prototype for a suite table.
 *
 * Use in the suite's public header. Defines the accessor
 * test_suite_get_<suite>() returning the case array and its length.
 */
#define TEST_SUITE_DECLARE(suite) const test_case_t *test_suite_get_##suite(size_t *out_count)

/**
 * @brief Open a suite case-table definition.
 *
 * Place TEST_REGISTER() entries between TEST_SUITE_BEGIN and TEST_SUITE_END.
 */
#define TEST_SUITE_BEGIN(suite) static const test_case_t k_cases_##suite[] = {
/**
 * @brief Register one case inside a TEST_SUITE_BEGIN/END block.
 *
 * @param plan_id Exact test-plan ID string, or "-" for helper bodies.
 * @param func    Test body function (test_result_t fn(void)).
 */
#define TEST_REGISTER(plan_id, func) { (plan_id), #func, (func) },

/**
 * @brief Close a suite case-table and define its getter.
 *
 * Defines test_suite_get_<suite>(size_t *out_count) returning the table.
 */
#define TEST_SUITE_END(suite)                                              \
    }                                                                      \
    ;                                                                      \
    const test_case_t *test_suite_get_##suite(size_t *out_count)           \
    {                                                                      \
        *out_count = sizeof(k_cases_##suite) / sizeof(k_cases_##suite[0]); \
        return k_cases_##suite;                                            \
    }

#endif /* EL2GO_TEST_SUITE_H */
