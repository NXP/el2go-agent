/*
 * Copyright 2023 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "el2go_blob_test.h"
#include "fsl_device_registers.h"
#include "app.h"

static struct test_suite_t test_suites[] = {
    {&testsuite_blob_internal, 0, 0, 0},
    {&testsuite_blob_external, 0, 0, 0},
    {0, 0, 0, 0}
};

void run_testsuite(struct test_suite_t *test_suite)
{
    test_suite->suite(test_suite);

    PRINTF_SET_COLOR(YELLOW);
    PRINTF("Running test suite %s\r\n", test_suite->name);

    uint32_t failed_tests = 0;
    uint32_t skipped_tests = 0;

    struct test_t *test = test_suite->test_list;
    for (int i = 0; i < test_suite->test_list_size; i++) {
        PRINTF_SET_COLOR(DEFAULT);
        PRINTF("> Executing test %s \r\n  Description: '%s'\r\n", test->name, test->description);

        struct test_result_t result = {TEST_PASSED};
        test->testcase(&result);
        if (result.status == TEST_FAILED) {
            PRINTF_SET_COLOR(RED);
            if (result.message != 0) {
                PRINTF("  %s", result.message);
                if (result.function != 0) {
                    PRINTF(" (%s:%d)\r\n", result.function, result.line);
                }
             } else {
                if (result.function != 0) {
                    PRINTF("  Failed at %s:%d\r\n", result.function, result.line);
                }
            }
            PRINTF("  Test %s - FAILED\r\n", test->name);
            failed_tests++;
        } else if (result.status== TEST_SKIPPED) {
            PRINTF_SET_COLOR(BLUE);
            if (result.message != 0) {
                PRINTF("  %s\r\n", result.message);
            }
            PRINTF("  Test %s - SKIPPED\r\n", test->name);
            skipped_tests++;
        } else {
            PRINTF_SET_COLOR(GREEN);
            PRINTF("  Test %s - PASSED\r\n", test->name);
        }

        test++;
    }

    if (failed_tests != 0) {
        PRINTF_SET_COLOR(CYAN);
        PRINTF("%d of %d FAILED\r\n",
               failed_tests, test_suite->test_list_size);
    }
    if (skipped_tests != 0) {
        PRINTF_SET_COLOR(CYAN);
        PRINTF("%d of %d SKIPPED\r\n",
               skipped_tests, test_suite->test_list_size);
    }

    if (failed_tests == 0) {
        PRINTF_SET_COLOR(GREEN);
        PRINTF("Test suite %s - PASSED\r\n", test_suite->name);
        test_suite->status = TEST_PASSED;
    } else {
        PRINTF_SET_COLOR(RED);
        PRINTF("Test suite %s - FAILED\r\n", test_suite->name);
        test_suite->status = TEST_FAILED;
    }
}

int main(void)
{
    BOARD_InitHardware();

    PRINTF_SET_COLOR(YELLOW);
    PRINTF("\r\n#### Start EL2GO blob tests ####\r\n");

    for (int i = 0; test_suites[i].suite != NULL; i++) {
        run_testsuite(&test_suites[i]);
    }

    PRINTF_SET_COLOR(MAGENTA);
    PRINTF("\r\n#### Summary ####\r\n");
    for (int i = 0; test_suites[i].suite != NULL; i++) {
        PRINTF_SET_COLOR(DEFAULT);
        PRINTF("Test suite %s -", test_suites[i].name);
        if (test_suites[i].status == TEST_PASSED) {
            PRINTF_SET_COLOR(GREEN);
            PRINTF(" PASSED\r\n");
        } else {
            PRINTF_SET_COLOR(RED);
            PRINTF(" FAILED\r\n");
        }
    }

    PRINTF_SET_COLOR(YELLOW);
    PRINTF("\r\n#### EL2GO blob tests finished ####\r\n");
    PRINTF_SET_COLOR(DEFAULT);

	while(1);
}