/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright 2026 NXP
 */
#ifndef __TEST_FRAMEWORK_H__
#define __TEST_FRAMEWORK_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

/* ============================================================================
 * Test Macros
 * ============================================================================
 */

#define TEST_ASSERT(condition)                                                 \
	do {                                                                   \
		if (!(condition)) {                                            \
			fprintf(stderr, "FAIL: %s:%d: Assertion failed: %s\n", \
				__FILE__, __LINE__, #condition);               \
			return false;                                          \
		}                                                              \
	} while (0)

#define TEST_ASSERT_EQUAL(expected, actual)                                   \
	do {                                                                  \
		if ((expected) != (actual)) {                                 \
			fprintf(stderr, "FAIL: %s:%d: Expected %d, got %d\n", \
				__FILE__, __LINE__, (int)(expected),          \
				(int)(actual));                               \
			return false;                                         \
		}                                                             \
	} while (0)

#define TEST_ASSERT_NOT_EQUAL(expected, actual)                            \
	do {                                                               \
		if ((expected) == (actual)) {                              \
			fprintf(stderr,                                    \
				"FAIL: %s:%d: Expected not equal to %d\n", \
				__FILE__, __LINE__, (int)(expected));      \
			return false;                                      \
		}                                                          \
	} while (0)

#define TEST_ASSERT_NULL(ptr)                                           \
	do {                                                            \
		if ((ptr) != NULL) {                                    \
			fprintf(stderr,                                 \
				"FAIL: %s:%d: Expected NULL pointer\n", \
				__FILE__, __LINE__);                    \
			return false;                                   \
		}                                                       \
	} while (0)

#define TEST_ASSERT_NOT_NULL(ptr)                                           \
	do {                                                                \
		if ((ptr) == NULL) {                                        \
			fprintf(stderr,                                     \
				"FAIL: %s:%d: Expected non-NULL pointer\n", \
				__FILE__, __LINE__);                        \
			return false;                                       \
		}                                                           \
	} while (0)

#define TEST_ASSERT_STRING_EQUAL(expected, actual)                            \
	do {                                                                  \
		if (strcmp((expected), (actual)) != 0) {                      \
			fprintf(stderr,                                       \
				"FAIL: %s:%d: Expected \"%s\", got \"%s\"\n", \
				__FILE__, __LINE__, (expected), (actual));    \
			return false;                                         \
		}                                                             \
	} while (0)

#define TEST_ASSERT_MEMORY_EQUAL(expected, actual, size)                   \
	do {                                                               \
		if (memcmp((expected), (actual), (size)) != 0) {           \
			fprintf(stderr,                                    \
				"FAIL: %s:%d: Memory comparison failed\n", \
				__FILE__, __LINE__);                       \
			return false;                                      \
		}                                                          \
	} while (0)

/* ============================================================================
 * Test Print Macros
 * ============================================================================
 */

/**
 * TEST_PRINT - Print informational message to stdout
 * @fmt: printf-style format string
 * @...: Variable arguments for format string
 *
 * Use for general test output and informational messages.
 */
#define TEST_PRINT(fmt, ...) printf("[TEST] " fmt, ##__VA_ARGS__)

/**
 * TEST_PRINT_INFO - Print informational message with newline
 * @fmt: printf-style format string
 * @...: Variable arguments for format string
 *
 * Convenience macro that automatically adds a newline.
 */
#define TEST_PRINT_INFO(fmt, ...) printf("[INFO] " fmt "\n", ##__VA_ARGS__)

/**
 * TEST_PRINT_WARN - Print warning message to stderr
 * @fmt: printf-style format string
 * @...: Variable arguments for format string
 *
 * Use for non-fatal warnings during test execution.
 */
#define TEST_PRINT_WARN(fmt, ...) \
	fprintf(stderr, "[WARN] " fmt "\n", ##__VA_ARGS__)

/**
 * TEST_PRINT_ERROR - Print error message to stderr
 * @fmt: printf-style format string
 * @...: Variable arguments for format string
 *
 * Use for error messages (typically before assertion failures).
 */
#define TEST_PRINT_ERROR(fmt, ...) \
	fprintf(stderr, "[ERROR] " fmt "\n", ##__VA_ARGS__)

/**
 * TEST_PRINT_DEBUG - Print debug message to stdout
 * @fmt: printf-style format string
 * @...: Variable arguments for format string
 *
 * Use for detailed debug information during test development.
 */
#define TEST_PRINT_DEBUG(fmt, ...) printf("[DEBUG] " fmt "\n", ##__VA_ARGS__)

typedef bool (*test_func_t)(void *params);

/**
 * test_framework_init - Initialize the test framework
 *
 * Must be called before registering any tests.
 */
void test_framework_init(void);

/**
 * test_framework_register - Register a test function
 * @name: Name of the test (for display purposes)
 * @func: Test function to execute
 * @params: Optional parameters to pass to the test function (can be NULL)
 *
 * Registers a test function to be executed by test_framework_run().
 */
void test_framework_register(const char *name, test_func_t func, void *params);

/**
 * test_framework_run - Run all registered tests
 *
 * Executes all registered test functions and reports results.
 *
 * Return: 0 if all tests passed, 1 if any test failed
 */
int test_framework_run(void);

/**
 * TEST_REGISTER - Convenience macro to register a test without parameters
 * @func: Test function name
 *
 * Automatically uses the function name as the test name.
 */
#define TEST_REGISTER(func) test_framework_register(#func, func, NULL)

/**
 * TEST_REGISTER_WITH_PARAMS - Register a test with parameters
 * @func: Test function name
 * @params: Parameters to pass to the test function
 *
 * Automatically uses the function name as the test name.
 */
#define TEST_REGISTER_WITH_PARAMS(func, params) \
	test_framework_register(#func, func, params)

#endif /* __TEST_FRAMEWORK_H__*/
