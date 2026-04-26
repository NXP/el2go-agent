// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright 2026 NXP
 */

#include "test_framework.h"

#define MAX_TESTS 256

typedef struct {
	const char *name;
	test_func_t func;
	void *params;
} test_entry_t;

static test_entry_t tests[MAX_TESTS];
static int test_count;

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

void test_framework_set_suite_teardown(test_teardown_func_t teardown,
				       void *params)
{
	suite_teardown = teardown;
	suite_teardown_params = params;
}

void test_framework_register(const char *name, test_func_t func, void *params)
{
	if (test_count >= MAX_TESTS) {
		TEST_PRINT_ERROR("Too many tests registered (max: %d)",
				 MAX_TESTS);
		exit(1);
	}

	if (!name || !func) {
		TEST_PRINT_ERROR("Invalid test (NULL name or function)");
		exit(1);
	}

	tests[test_count].name = name;
	tests[test_count].func = func;
	tests[test_count].params = params;
	test_count++;
}

int test_framework_run(void)
{
	int passed = 0;
	int failed = 0;

	if (test_count == 0) {
		TEST_PRINT_WARN("No tests registered");
		return 0;
	}

	printf("\n");
	printf("========================================\n");
	printf("Running %d tests\n", test_count);
	printf("========================================\n\n");

	if (suite_setup) {
		printf("[ SETUP  ] Running suite setup\n");
		suite_setup(suite_setup_params);
		printf("\n");
	}

	for (int i = 0; i < test_count; i++) {
		printf("[  RUN   ] %s\n", tests[i].name);
		fflush(stdout);

		bool result = tests[i].func(tests[i].params);

		if (result) {
			printf("[  PASS  ] %s\n", tests[i].name);
			passed++;
		} else {
			printf("[  FAIL  ] %s\n", tests[i].name);
			failed++;
		}
		printf("\n");
		fflush(stdout);
	}

	if (suite_teardown) {
		printf("[TEARDOWN] Running suite teardown\n");
		suite_teardown(suite_teardown_params);
		printf("\n");
	}

	printf("========================================\n");
	printf("Test Results:\n");
	printf("  Passed: %d/%d\n", passed, test_count);
	printf("  Failed: %d/%d\n", failed, test_count);
	printf("========================================\n");

	if (failed > 0) {
		printf("\nFAILURE: %d test(s) failed\n", failed);
		return 1;
	}
	printf("\nSUCCESS: All tests passed\n");
	return 0;
}
