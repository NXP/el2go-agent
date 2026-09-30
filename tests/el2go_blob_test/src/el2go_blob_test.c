/*
 * Copyright 2023-2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <psa/crypto_values.h>

#include "el2go_blob_test.h"
#include "el2go_blob_test_reader.h"
#include "el2go_blob_test_parser.h"
#include "el2go_blob_test_platform.h"

static struct test_suite_t test_suites[] = { { &testsuite_blob_generic, 0, 0, 0 }, { 0, 0, 0, 0 } };

static void run_testsuite(struct test_suite_t *test_suite)
{
    test_suite->suite(test_suite);

    LOG_SET_COLOR(YELLOW);
    LOG("Running test suite %s\r\n", test_suite->name);

    uint32_t failed_tests = 0U;
    uint32_t skipped_tests = 0U;
    uint32_t passed_tests = 0U;

    int64_t elapsed_time = 0;
    int64_t total_elapsed_time = 0;

    struct test_t *test = test_suite->test_list;
    for (size_t i = 0U; i < test_suite->test_list_size; i++) {
        LOG_SET_COLOR(DEFAULT);
        LOG("> Executing test %s \r\n", test->name);
        LOG("%*sDescription: '%s'\r\n", TEST, "", test->description);

        int64_t start_time = el2go_blob_test_uptime_ms();

        struct test_result_t result = { TEST_PASSED };
        if (test->testcase != NULL) {
            test->testcase(&result);
        } else {
            uint8_t *blob = NULL;
            size_t blob_length = 0;

            read_blob_data(test->data, test->data_length, &blob, &blob_length, &result);

            if (result.status == TEST_PASSED) {
                parse_and_run_test(blob, blob_length, &result);
                free(blob);
            }
        }

        elapsed_time = el2go_blob_test_uptime_delta(&start_time);

        if (result.status == TEST_FAILED) {
            LOG_SET_COLOR(RED);
            if (result.message != NULL) {
                LOG("%*s%s", TEST, "", result.message);
                if (result.function != NULL) {
                    LOG(" (%s:%d)\r\n", result.function, result.line);
                }
            } else {
                if (result.function != NULL) {
                    LOG("%*sFailed at %s:%d\r\n", TEST, "", result.function, result.line);
                }
            }
            LOG("%*sTest %s - FAILED (%d ms)\r\n", TEST, "", test->name, (int)elapsed_time);
            failed_tests++;
            total_elapsed_time += elapsed_time;
        } else if (result.status == TEST_SKIPPED) {
            LOG_SET_COLOR(BLUE);
            if (result.message != NULL) {
                LOG("  %s\r\n", result.message);
            }
            LOG("%*sTest %s - SKIPPED\r\n", TEST, "", test->name);
            skipped_tests++;
        } else {
            LOG_SET_COLOR(GREEN);
            LOG("%*sTest %s - PASSED (%d ms)\r\n", TEST, "", test->name, (int)elapsed_time);
            passed_tests++;
            total_elapsed_time += elapsed_time;
        }

        test++;
    }

    if (failed_tests != 0U) {
        LOG_SET_COLOR(MAGENTA);
        LOG("%d of %d FAILED\r\n", failed_tests, test_suite->test_list_size);
    }
    if (skipped_tests != 0U) {
        LOG_SET_COLOR(CYAN);
        LOG("%d of %d SKIPPED\r\n", skipped_tests, test_suite->test_list_size);
    }
    if (passed_tests != 0U) {
        LOG_SET_COLOR(CYAN);
        LOG("%d of %d PASSED\r\n", passed_tests, test_suite->test_list_size);
    }

    if (failed_tests == 0U && passed_tests != 0U) {
        LOG_SET_COLOR(GREEN);
        LOG("Test suite %s - PASSED (%d ms)\r\n", test_suite->name, (int)total_elapsed_time);
        test_suite->status = TEST_PASSED;
    } else if (failed_tests == 0U && passed_tests == 0U) {
        LOG_SET_COLOR(BLUE);
        LOG("Test suite %s - SKIPPED\r\n", test_suite->name);
        test_suite->status = TEST_SKIPPED;
    } else {
        LOG_SET_COLOR(RED);
        LOG("Test suite %s - FAILED (%d ms)\r\n", test_suite->name, (int)total_elapsed_time);
        test_suite->status = TEST_FAILED;
    }

    test_suite->elapsed_time = (uint32_t)total_elapsed_time;
}

int main(void)
{
    el2go_blob_test_platform_init();

    psa_status_t psa_status = el2go_blob_test_secure_storage_init();
    if (psa_status != PSA_SUCCESS) {
        LOG("Secure storage init failed (%" PRId32 "), aborting.\r\n", psa_status);
        return 1;
    }

    LOG_SET_COLOR(YELLOW);
    LOG("\r\n#### Start EL2GO blob tests ####\r\n");

    for (int i = 0; test_suites[i].suite != NULL; i++) {
        run_testsuite(&test_suites[i]);
    }

    LOG_SET_COLOR(YELLOW);
    LOG("\r\n#### Summary ####\r\n");
    for (int i = 0; test_suites[i].suite != NULL; i++) {
        LOG_SET_COLOR(DEFAULT);
        LOG("Test suite %s -", test_suites[i].name);
        if (test_suites[i].status == TEST_PASSED) {
            LOG_SET_COLOR(GREEN);
            LOG(" PASSED (%d ms)\r\n", test_suites[i].elapsed_time);
        } else if (test_suites[i].status == TEST_SKIPPED) {
            LOG_SET_COLOR(BLUE);
            LOG(" SKIPPED\r\n");
        } else {
            LOG_SET_COLOR(RED);
            LOG(" FAILED (%d ms)\r\n", test_suites[i].elapsed_time);
        }
    }

    LOG_SET_COLOR(YELLOW);
    LOG("\r\n#### EL2GO blob tests finished ####\r\n");
    LOG_SET_COLOR(DEFAULT);

    while (true) {
        ;
    }
}
