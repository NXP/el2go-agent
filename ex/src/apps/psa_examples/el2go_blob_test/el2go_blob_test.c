/*
 * Copyright 2023-2024 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "el2go_blob_test.h"

#ifndef __ZEPHYR__
#include "app.h"
#endif

static struct test_suite_t test_suites[] = {
    {&testsuite_blob_internal, 0, 0, 0},
    {&testsuite_blob_external, 0, 0, 0},
    {0, 0, 0, 0}
};

void run_testsuite(struct test_suite_t *test_suite)
{
    test_suite->suite(test_suite);

    LOG_SET_COLOR(YELLOW);
    LOG("Running test suite %s\r\n", test_suite->name);

    uint32_t failed_tests = 0;
    uint32_t skipped_tests = 0;
    uint32_t passed_tests = 0;

    struct test_t *test = test_suite->test_list;
    for (int i = 0; i < test_suite->test_list_size; i++) {
        LOG_SET_COLOR(DEFAULT);
        LOG("> Executing test %s \r\n  Description: '%s'\r\n", test->name, test->description);

        struct test_result_t result = {TEST_PASSED};
        test->testcase(&result);
        if (result.status == TEST_FAILED) {
            LOG_SET_COLOR(RED);
            if (result.message != 0) {
                LOG("  %s", result.message);
                if (result.function != 0) {
                    LOG(" (%s:%d)\r\n", result.function, result.line);
                }
             } else {
                if (result.function != 0) {
                    LOG("  Failed at %s:%d\r\n", result.function, result.line);
                }
            }
            LOG("  Test %s - FAILED\r\n", test->name);
            failed_tests++;
        } else if (result.status== TEST_SKIPPED) {
            LOG_SET_COLOR(BLUE);
            if (result.message != 0) {
                LOG("  %s\r\n", result.message);
            }
            LOG("  Test %s - SKIPPED\r\n", test->name);
            skipped_tests++;
        } else {
            LOG_SET_COLOR(GREEN);
            LOG("  Test %s - PASSED\r\n", test->name);
            passed_tests++;
        }

        test++;
    }

    if (failed_tests != 0) {
        LOG_SET_COLOR(CYAN);
        LOG("%d of %d FAILED\r\n",
               failed_tests, test_suite->test_list_size);
    }
    if (skipped_tests != 0) {
        LOG_SET_COLOR(CYAN);
        LOG("%d of %d SKIPPED\r\n",
               skipped_tests, test_suite->test_list_size);
    }
    if (passed_tests != 0) {
        LOG_SET_COLOR(CYAN);
        LOG("%d of %d PASSED\r\n",
               passed_tests, test_suite->test_list_size);
    }

    if (failed_tests == 0) {
        LOG_SET_COLOR(GREEN);
        LOG("Test suite %s - PASSED\r\n", test_suite->name);
        test_suite->status = TEST_PASSED;
    } else {
        LOG_SET_COLOR(RED);
        LOG("Test suite %s - FAILED\r\n", test_suite->name);
        test_suite->status = TEST_FAILED;
    }
}

int main(void)
{
#ifndef __ZEPHYR__
    BOARD_InitHardware();
#endif
    LOG_SET_COLOR(YELLOW);
    LOG("\r\n#### Start EL2GO blob tests ####\r\n");

    for (int i = 0; test_suites[i].suite != NULL; i++) {
        run_testsuite(&test_suites[i]);
    }

    LOG_SET_COLOR(MAGENTA);
    LOG("\r\n#### Summary ####\r\n");
    for (int i = 0; test_suites[i].suite != NULL; i++) {
        LOG_SET_COLOR(DEFAULT);
        LOG("Test suite %s -", test_suites[i].name);
        if (test_suites[i].status == TEST_PASSED) {
            LOG_SET_COLOR(GREEN);
            LOG(" PASSED\r\n");
        } else {
            LOG_SET_COLOR(RED);
            LOG(" FAILED\r\n");
        }
    }

    LOG_SET_COLOR(YELLOW);
    LOG("\r\n#### EL2GO blob tests finished ####\r\n");
    LOG_SET_COLOR(DEFAULT);

    while(1);
}