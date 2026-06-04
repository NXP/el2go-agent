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
 * Test Print Macros
 * ============================================================================
 */

/**
 * TEST_PRINT - Print formatted message to specified stream
 * @stream: Output stream (stdout, stderr, etc.)
 * @fmt: printf-style format string
 * @...: Variable arguments for format string
 *
 * Base macro used by all other print macros.
 */
#define TEST_PRINT(stream, fmt, ...) \
	(void)fprintf(stream, "[TEST] " fmt, ##__VA_ARGS__)

/**
 * TEST_PRINT_FAIL - Print failure message with file and line number
 * @fmt: printf-style format string
 * @...: Variable arguments for format string
 *
 * Prints a formatted failure message with file location information.
 * Use for custom test failures without using assertion macros.
 */
#define TEST_PRINT_FAIL(fmt, ...)                                        \
	TEST_PRINT(stdout, "FAIL: %s:%d: " fmt "\n", __FILE__, __LINE__, \
		   ##__VA_ARGS__)

/* ============================================================================
 * Test Macros
 * ============================================================================
 */

#define TEST_ASSERT(condition)                                               \
	do {                                                                 \
		if (!(condition)) {                                          \
			TEST_PRINT_FAIL("Assertion failed: %s", #condition); \
			return false;                                        \
		}                                                            \
	} while (0)

#define TEST_ASSERT_EQUAL(expected, actual)                              \
	do {                                                             \
		if ((expected) != (actual)) {                            \
			TEST_PRINT_FAIL("Expected %d, got %d",           \
					(int)(expected), (int)(actual)); \
			return false;                                    \
		}                                                        \
	} while (0)

#define TEST_ASSERT_NOT_EQUAL(expected, actual)                     \
	do {                                                        \
		if ((expected) == (actual)) {                       \
			TEST_PRINT_FAIL("Expected not equal to %d", \
					(int)(expected));           \
			return false;                               \
		}                                                   \
	} while (0)

#define TEST_ASSERT_NULL(ptr)                                     \
	do {                                                      \
		if ((ptr) != NULL) {                              \
			TEST_PRINT_FAIL("Expected NULL pointer"); \
			return false;                             \
		}                                                 \
	} while (0)

#define TEST_ASSERT_NOT_NULL(ptr)                                     \
	do {                                                          \
		if ((ptr) == NULL) {                                  \
			TEST_PRINT_FAIL("Expected non-NULL pointer"); \
			return false;                                 \
		}                                                     \
	} while (0)

#define TEST_ASSERT_PTR_EQUAL(expected, actual)                                \
	do {                                                                   \
		if ((expected) != (actual)) {                                  \
			TEST_PRINT_FAIL("Expected pointer %p, got %p",         \
					(void *)(expected), (void *)(actual)); \
			return false;                                          \
		}                                                              \
	} while (0)

#define TEST_ASSERT_STRING_EQUAL(expected, actual)                     \
	do {                                                           \
		if (strcmp((expected), (actual)) != 0) {               \
			TEST_PRINT_FAIL("Expected \"%s\", got \"%s\"", \
					(expected), (actual));         \
			return false;                                  \
		}                                                      \
	} while (0)

#define TEST_ASSERT_MEMORY_EQUAL(expected, actual, size)             \
	do {                                                         \
		if (memcmp((expected), (actual), (size)) != 0) {     \
			TEST_PRINT_FAIL("Memory comparison failed"); \
			return false;                                \
		}                                                    \
	} while (0)

#define TEST_ASSERT_GOTO(condition, label)                                   \
	do {                                                                 \
		if (!(condition)) {                                          \
			TEST_PRINT_FAIL("Assertion failed: %s", #condition); \
			test_status = false;                                 \
			goto label;                                          \
		}                                                            \
	} while (0)

#define TEST_ASSERT_EQUAL_GOTO(expected, actual, label)                  \
	do {                                                             \
		if ((expected) != (actual)) {                            \
			TEST_PRINT_FAIL("Expected %d, got %d",           \
					(int)(expected), (int)(actual)); \
			test_status = false;                             \
			goto label;                                      \
		}                                                        \
	} while (0)

#define TEST_ASSERT_NOT_EQUAL_GOTO(expected, actual, label)         \
	do {                                                        \
		if ((expected) == (actual)) {                       \
			TEST_PRINT_FAIL("Expected not equal to %d", \
					(int)(expected));           \
			test_status = false;                        \
			goto label;                                 \
		}                                                   \
	} while (0)

#define TEST_ASSERT_NULL_GOTO(ptr, label)                         \
	do {                                                      \
		if ((ptr) != NULL) {                              \
			TEST_PRINT_FAIL("Expected NULL pointer"); \
			test_status = false;                      \
			goto label;                               \
		}                                                 \
	} while (0)

#define TEST_ASSERT_NOT_NULL_GOTO(ptr, label)                         \
	do {                                                          \
		if ((ptr) == NULL) {                                  \
			TEST_PRINT_FAIL("Expected non-NULL pointer"); \
			test_status = false;                          \
			goto label;                                   \
		}                                                     \
	} while (0)

#define TEST_ASSERT_PTR_EQUAL_GOTO(expected, actual, label)                    \
	do {                                                                   \
		if ((expected) != (actual)) {                                  \
			TEST_PRINT_FAIL("Expected pointer %p, got %p",         \
					(void *)(expected), (void *)(actual)); \
			test_status = false;                                   \
			goto label;                                            \
		}                                                              \
	} while (0)

#define TEST_ASSERT_STRING_EQUAL_GOTO(expected, actual, label)         \
	do {                                                           \
		if (strcmp((expected), (actual)) != 0) {               \
			TEST_PRINT_FAIL("Expected \"%s\", got \"%s\"", \
					(expected), (actual));         \
			test_status = false;                           \
			goto label;                                    \
		}                                                      \
	} while (0)

#define TEST_ASSERT_MEMORY_EQUAL_GOTO(expected, actual, size, label) \
	do {                                                         \
		if (memcmp((expected), (actual), (size)) != 0) {     \
			TEST_PRINT_FAIL("Memory comparison failed"); \
			test_status = false;                         \
			goto label;                                  \
		}                                                    \
	} while (0)

#define TEST_ASSERT_CONTINUE(condition)                                      \
	do {                                                                 \
		if (!(condition)) {                                          \
			TEST_PRINT_FAIL("Assertion failed: %s", #condition); \
			test_status = false;                                 \
		}                                                            \
	} while (0)

#define TEST_ASSERT_EQUAL_CONTINUE(expected, actual)                     \
	do {                                                             \
		if ((expected) != (actual)) {                            \
			TEST_PRINT_FAIL("Expected %d, got %d",           \
					(int)(expected), (int)(actual)); \
			test_status = false;                             \
		}                                                        \
	} while (0)

#define TEST_ASSERT_NOT_EQUAL_CONTINUE(expected, actual)            \
	do {                                                        \
		if ((expected) == (actual)) {                       \
			TEST_PRINT_FAIL("Expected not equal to %d", \
					(int)(expected));           \
			test_status = false;                        \
		}                                                   \
	} while (0)

#define TEST_ASSERT_NULL_CONTINUE(ptr)                            \
	do {                                                      \
		if ((ptr) != NULL) {                              \
			TEST_PRINT_FAIL("Expected NULL pointer"); \
			test_status = false;                      \
		}                                                 \
	} while (0)

#define TEST_ASSERT_NOT_NULL_CONTINUE(ptr)                            \
	do {                                                          \
		if ((ptr) == NULL) {                                  \
			TEST_PRINT_FAIL("Expected non-NULL pointer"); \
			test_status = false;                          \
		}                                                     \
	} while (0)

#define TEST_ASSERT_PTR_EQUAL_CONTINUE(expected, actual)                       \
	do {                                                                   \
		if ((expected) != (actual)) {                                  \
			TEST_PRINT_FAIL("Expected pointer %p, got %p",         \
					(void *)(expected), (void *)(actual)); \
			test_status = false;                                   \
		}                                                              \
	} while (0)

#define TEST_ASSERT_STRING_EQUAL_CONTINUE(expected, actual)            \
	do {                                                           \
		if (strcmp((expected), (actual)) != 0) {               \
			TEST_PRINT_FAIL("Expected \"%s\", got \"%s\"", \
					(expected), (actual));         \
			test_status = false;                           \
		}                                                      \
	} while (0)

#define TEST_ASSERT_MEMORY_EQUAL_CONTINUE(expected, actual, size)    \
	do {                                                         \
		if (memcmp((expected), (actual), (size)) != 0) {     \
			TEST_PRINT_FAIL("Memory comparison failed"); \
			test_status = false;                         \
		}                                                    \
	} while (0)

/* ============================================================================
 * Additional Test Print Macros
 * ============================================================================
 */

/**
 * TEST_PRINT_INFO - Print informational message with newline
 * @fmt: printf-style format string
 * @...: Variable arguments for format string
 *
 * Convenience macro that automatically adds a newline.
 */
#define TEST_PRINT_INFO(fmt, ...) \
	TEST_PRINT(stdout, "[INFO] " fmt "\n", ##__VA_ARGS__)

/**
 * TEST_PRINT_WARN - Print warning message to stderr
 * @fmt: printf-style format string
 * @...: Variable arguments for format string
 *
 * Use for non-fatal warnings during test execution.
 */
#define TEST_PRINT_WARN(fmt, ...) \
	TEST_PRINT(stderr, "[WARN] " fmt "\n", ##__VA_ARGS__)

/**
 * TEST_PRINT_ERROR - Print error message to stderr
 * @fmt: printf-style format string
 * @...: Variable arguments for format string
 *
 * Use for error messages (typically before assertion failures).
 */
#define TEST_PRINT_ERROR(fmt, ...) \
	TEST_PRINT(stderr, "[ERROR] " fmt "\n", ##__VA_ARGS__)

/**
 * TEST_PRINT_DEBUG - Print debug message to stdout
 * @fmt: printf-style format string
 * @...: Variable arguments for format string
 *
 * Use for detailed debug information during test development.
 */
#define TEST_PRINT_DEBUG(fmt, ...) \
	TEST_PRINT(stdout, "[DEBUG] " fmt "\n", ##__VA_ARGS__)

typedef bool (*test_func_t)(void *params);
typedef void (*test_setup_func_t)(void *params);
typedef void (*test_teardown_func_t)(void *params);

/**
 * test_framework_init - Initialize the test framework
 *
 * Must be called before registering any tests.
 */
void test_framework_init(void);

/**
 * test_framework_set_suite_setup - Set suite-level setup function
 * @setup: Function to call before running any tests in the suite
 * @params: Optional parameters to pass to the setup function (can be NULL)
 *
 * The setup function will be called once before the first test runs.
 * Can be NULL to disable suite setup.
 */
void test_framework_set_suite_setup(test_setup_func_t setup, void *params);

/**
 * test_framework_set_suite_teardown - Set suite-level teardown function
 * @teardown: Function to call after all tests have run
 * @params: Optional parameters to pass to the teardown function (can be NULL)
 *
 * The teardown function will be called once after the last test completes.
 * Can be NULL to disable suite teardown.
 */
void test_framework_set_suite_teardown(test_teardown_func_t teardown,
				       void *params);

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

/**
 * TEST_SET_SUITE_SETUP - Set suite setup function without parameters
 * @func: Setup function name
 *
 * Convenience macro to set suite setup without parameters.
 */
#define TEST_SET_SUITE_SETUP(func) test_framework_set_suite_setup(func, NULL)

/**
 * TEST_SET_SUITE_SETUP_WITH_PARAMS - Set suite setup function with parameters
 * @func: Setup function name
 * @params: Parameters to pass to the setup function
 *
 * Macro to set suite setup with custom parameters.
 */
#define TEST_SET_SUITE_SETUP_WITH_PARAMS(func, params) \
	test_framework_set_suite_setup(func, params)

/**
 * TEST_SET_SUITE_TEARDOWN - Set suite teardown function without parameters
 * @func: Teardown function name
 *
 * Convenience macro to set suite teardown without parameters.
 */
#define TEST_SET_SUITE_TEARDOWN(func) \
	test_framework_set_suite_teardown(func, NULL)

/**
 * TEST_SET_SUITE_TEARDOWN_WITH_PARAMS - Set suite teardown function with parameters
 * @func: Teardown function name
 * @params: Parameters to pass to the teardown function
 *
 * Macro to set suite teardown with custom parameters.
 */
#define TEST_SET_SUITE_TEARDOWN_WITH_PARAMS(func, params) \
	test_framework_set_suite_teardown(func, params)

#endif /* __TEST_FRAMEWORK_H__*/
