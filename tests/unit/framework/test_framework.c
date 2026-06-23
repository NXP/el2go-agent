/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */
#include "builtin_macros.h"

#include "test_framework.h"
#include "builtin_macros.h"

#define MAX_TESTS 256

typedef struct {
    const char *name;
    test_func_t func;
    void *params;
} test_entry_t;

static test_entry_t tests[MAX_TESTS];
static size_t test_count;

static test_setup_func_t suite_setup;
static void *suite_setup_params;
static test_teardown_func_t suite_teardown;
static void *suite_teardown_params;

void test_framework_init(void)
{
    test_count = 0;
    suite_setup = NULL;
    suite_setup_params = NULL;
    suite_teardown = NULL;
    suite_teardown_params = NULL;
    memset(tests, 0, sizeof(tests));
}

void test_framework_set_suite_setup(test_setup_func_t setup, void *params)
{
    suite_setup = setup;
    suite_setup_params = params;
}

void test_framework_set_suite_teardown(test_teardown_func_t teardown, void *params)
{
    suite_teardown = teardown;
    suite_teardown_params = params;
}

void test_framework_register(const char *name, test_func_t func, void *params)
{
    if (!name || !func) {
        TEST_PRINT_ERROR("Invalid test (NULL name or function)");
        exit(1);
    }

    if (test_count >= MAX_TESTS) {
        TEST_PRINT_ERROR("Too many tests registered (max: %d)", MAX_TESTS);
        exit(1);
    }

    tests[test_count].name = name;
    tests[test_count].func = func;
    tests[test_count].params = params;
    test_count++;
}

int test_framework_run(void)
{
    size_t passed = 0;
    size_t failed = 0;
    size_t i = 0;

    if (test_count == 0) {
        TEST_PRINT_WARN("No tests registered");
        return 0;
    }

    TEST_PRINT_RAW("\n");
    TEST_PRINT_RAW("========================================");
    TEST_PRINT_RAW("Running %ld tests", test_count);
    TEST_PRINT_RAW("========================================\n");

    if (suite_setup) {
        TEST_PRINT_INFO("Running suite setup\n");
        suite_setup(suite_setup_params);
        TEST_PRINT_RAW("");
    }

    for (i = 0; i < test_count; i++) {
        TEST_PRINT_INFO("[RUN] %s\n", tests[i].name);
        (void)fflush(stdout);

        bool result = tests[i].func(tests[i].params);

        if (result) {
            TEST_PRINT_RESULT("PASS", tests[i].name);
            if (INC_OVERFLOW(passed, 1)) {
                TEST_PRINT_ERROR("Passed counter overflow");
                return 1;
            }
        } else {
            TEST_PRINT_RESULT("FAIL", tests[i].name);
            if (INC_OVERFLOW(failed, 1)) {
                TEST_PRINT_ERROR("Failed counter overflow");
                return 1;
            }
        }
        TEST_PRINT_RAW("");
        (void)fflush(stdout);
    }

    if (suite_teardown) {
        TEST_PRINT_INFO("Running suite teardown\n");
        suite_teardown(suite_teardown_params);
        TEST_PRINT_RAW("");
    }

    TEST_PRINT_RAW("========================================");
    TEST_PRINT_RAW("Test Results:");
    TEST_PRINT_RAW("  Passed: %ld/%ld", passed, test_count);
    TEST_PRINT_RAW("  Failed: %ld/%ld", failed, test_count);
    TEST_PRINT_RAW("========================================");

    if (failed > 0) {
        TEST_PRINT(stdout, "FAILURE: %ld test(s) failed\n", failed);
        return 1;
    }
    TEST_PRINT(stdout, "SUCCESS: All tests passed\n");
    return 0;
}
