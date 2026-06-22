/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */
#ifndef __TEST_FRAMEWORK_H__
#define __TEST_FRAMEWORK_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>

/**
 * @defgroup test_framework Test Framework
 * @brief Lightweight unit test framework for EL2GO device link reference tests.
 *
 * This framework provides macros and functions for registering, running,
 * and reporting unit tests. It supports suite-level setup/teardown,
 * per-test parameters, and a variety of assertion styles.
 *
 * @{
 */

/* ===========================================================================
 * Test Print Macros
 * ============================================================================
 */

/**
 * @def TEST_PRINT(stream, fmt, ...)
 * @brief Print a formatted message to the specified stream with the EL2GO-TEST prefix.
 *
 * Base macro used by all other print macros.
 *
 * @param stream Output stream (e.g. @c stdout, @c stderr).
 * @param fmt    printf-style format string.
 * @param ...    Variable arguments for the format string.
 */
#define TEST_PRINT(stream, fmt, ...) \
	(void)fprintf(stream, "[EL2GO-TEST] " fmt, ##__VA_ARGS__)

/**
 * @def TEST_PRINT_RAW(fmt, ...)
 * @brief Print a message to @c stdout without any prefix.
 *
 * Prints a formatted message followed by a newline, without any tag prefix.
 *
 * @param fmt printf-style format string.
 * @param ... Variable arguments for the format string.
 */
#define TEST_PRINT_RAW(fmt, ...) (void)fprintf(stdout, fmt "\n", ##__VA_ARGS__)

/**
 * @def TEST_PRINT_FAIL(fmt, ...)
 * @brief Print a failure message including the source file and line number.
 *
 * Prints a formatted failure message with file location information.
 * Use for custom test failures without using assertion macros.
 *
 * @param fmt printf-style format string.
 * @param ... Variable arguments for the format string.
 */
#define TEST_PRINT_FAIL(fmt, ...)                                        \
	TEST_PRINT(stdout, "FAIL: %s:%d: " fmt "\n", __FILE__, __LINE__, \
		   ##__VA_ARGS__)

/**
 * @def TEST_PRINT_INFO(fmt, ...)
 * @brief Print an informational message to @c stdout.
 *
 * Convenience macro that automatically adds the @c [INFO] tag and a newline.
 *
 * @param fmt printf-style format string.
 * @param ... Variable arguments for the format string.
 */
#define TEST_PRINT_INFO(fmt, ...) \
	TEST_PRINT(stdout, "[INFO] " fmt "\n", ##__VA_ARGS__)

/**
 * @def TEST_PRINT_WARN(fmt, ...)
 * @brief Print a warning message to @c stderr.
 *
 * Use for non-fatal warnings during test execution.
 *
 * @param fmt printf-style format string.
 * @param ... Variable arguments for the format string.
 */
#define TEST_PRINT_WARN(fmt, ...) \
	TEST_PRINT(stderr, "[WARN] " fmt "\n", ##__VA_ARGS__)

/**
 * @def TEST_PRINT_ERROR(fmt, ...)
 * @brief Print an error message to @c stderr.
 *
 * Use for error messages, typically before assertion failures.
 *
 * @param fmt printf-style format string.
 * @param ... Variable arguments for the format string.
 */
#define TEST_PRINT_ERROR(fmt, ...) \
	TEST_PRINT(stderr, "[ERROR] " fmt "\n", ##__VA_ARGS__)

/**
 * @def TEST_PRINT_DEBUG(fmt, ...)
 * @brief Print a debug message to @c stdout.
 *
 * Use for detailed debug information during test development.
 *
 * @param fmt printf-style format string.
 * @param ... Variable arguments for the format string.
 */
#define TEST_PRINT_DEBUG(fmt, ...) \
	TEST_PRINT(stdout, "[DEBUG] " fmt "\n", ##__VA_ARGS__)

/**
 * @def TEST_PRINT_RESULT(result, name)
 * @brief Print a formatted test result message.
 *
 * @param result Test result string (e.g. @c "PASS" or @c "FAIL").
 * @param name   Test name string.
 */
#define TEST_PRINT_RESULT(result, name) \
	TEST_PRINT(stdout, "[RESULT] [ %s ] %s\n", result, name)

/* ============================================================================
 * Test Macros
 * ============================================================================
 */

/**
 * @def TEST_ASSERT(condition)
 * @brief Assert that @p condition is true; return @c false on failure.
 *
 * @param condition Expression to evaluate.
 */
#define TEST_ASSERT(condition)                                               \
	do {                                                                 \
		if (!(condition)) {                                          \
			TEST_PRINT_FAIL("Assertion failed: %s", #condition); \
			return false;                                        \
		}                                                            \
	} while (0)

/**
 * @def TEST_ASSERT_EQUAL(expected, actual)
 * @brief Assert that @p expected == @p actual; return @c false on failure.
 *
 * @param expected Expected integer value.
 * @param actual   Actual integer value.
 */
#define TEST_ASSERT_EQUAL(expected, actual)                              \
	do {                                                             \
		if ((expected) != (actual)) {                            \
			TEST_PRINT_FAIL("Expected %d, got %d",           \
					(int)(expected), (int)(actual)); \
			return false;                                    \
		}                                                        \
	} while (0)

/**
 * @def TEST_ASSERT_NOT_EQUAL(expected, actual)
 * @brief Assert that @p expected != @p actual; return @c false on failure.
 *
 * @param expected Value that @p actual must not equal.
 * @param actual   Actual integer value.
 */
#define TEST_ASSERT_NOT_EQUAL(expected, actual)                     \
	do {                                                        \
		if ((expected) == (actual)) {                       \
			TEST_PRINT_FAIL("Expected not equal to %d", \
					(int)(expected));           \
			return false;                               \
		}                                                   \
	} while (0)

/**
 * @def TEST_ASSERT_NULL(ptr)
 * @brief Assert that @p ptr is @c NULL; return @c false on failure.
 *
 * @param ptr Pointer to check.
 */
#define TEST_ASSERT_NULL(ptr)                                     \
	do {                                                      \
		if ((ptr) != NULL) {                              \
			TEST_PRINT_FAIL("Expected NULL pointer"); \
			return false;                             \
		}                                                 \
	} while (0)

/**
 * @def TEST_ASSERT_NOT_NULL(ptr)
 * @brief Assert that @p ptr is not @c NULL; return @c false on failure.
 *
 * @param ptr Pointer to check.
 */
#define TEST_ASSERT_NOT_NULL(ptr)                                     \
	do {                                                          \
		if ((ptr) == NULL) {                                  \
			TEST_PRINT_FAIL("Expected non-NULL pointer"); \
			return false;                                 \
		}                                                     \
	} while (0)

/**
 * @def TEST_ASSERT_PTR_EQUAL(expected, actual)
 * @brief Assert that pointers @p expected and @p actual are equal; return @c false on failure.
 *
 * @param expected Expected pointer value.
 * @param actual   Actual pointer value.
 */
#define TEST_ASSERT_PTR_EQUAL(expected, actual)                                \
	do {                                                                   \
		if ((expected) != (actual)) {                                  \
			TEST_PRINT_FAIL("Expected pointer %p, got %p",         \
					(void *)(expected), (void *)(actual)); \
			return false;                                          \
		}                                                              \
	} while (0)

/**
 * @def TEST_ASSERT_STRING_EQUAL(expected, actual)
 * @brief Assert that strings @p expected and @p actual are equal; return @c false on failure.
 *
 * Uses @c strcmp internally.
 *
 * @param expected Expected C string.
 * @param actual   Actual C string.
 */
#define TEST_ASSERT_STRING_EQUAL(expected, actual)                     \
	do {                                                           \
		if (strcmp((expected), (actual)) != 0) {               \
			TEST_PRINT_FAIL("Expected \"%s\", got \"%s\"", \
					(expected), (actual));         \
			return false;                                  \
		}                                                      \
	} while (0)

/**
 * @def TEST_ASSERT_MEMORY_EQUAL(expected, actual, size)
 * @brief Assert that two memory regions are equal; return @c false on failure.
 *
 * Uses @c memcmp internally.
 *
 * @param expected Pointer to expected memory region.
 * @param actual   Pointer to actual memory region.
 * @param size     Number of bytes to compare.
 */
#define TEST_ASSERT_MEMORY_EQUAL(expected, actual, size)             \
	do {                                                         \
		if (memcmp((expected), (actual), (size)) != 0) {     \
			TEST_PRINT_FAIL("Memory comparison failed"); \
			return false;                                \
		}                                                    \
	} while (0)

/**
 * @def TEST_ASSERT_GOTO(condition, label)
 * @brief Assert that @p condition is true; set @c test_status and goto @p label on failure.
 *
 * @param condition Expression to evaluate.
 * @param label     Label to jump to on failure.
 */
#define TEST_ASSERT_GOTO(condition, label)                                   \
	do {                                                                 \
		if (!(condition)) {                                          \
			TEST_PRINT_FAIL("Assertion failed: %s", #condition); \
			test_status = false;                                 \
			goto label;                                          \
		}                                                            \
	} while (0)

/**
 * @def TEST_ASSERT_EQUAL_GOTO(expected, actual, label)
 * @brief Assert that @p expected == @p actual; set @c test_status and goto @p label on failure.
 *
 * @param expected Expected integer value.
 * @param actual   Actual integer value.
 * @param label    Label to jump to on failure.
 */
#define TEST_ASSERT_EQUAL_GOTO(expected, actual, label)                  \
	do {                                                             \
		if ((expected) != (actual)) {                            \
			TEST_PRINT_FAIL("Expected %d, got %d",           \
					(int)(expected), (int)(actual)); \
			test_status = false;                             \
			goto label;                                      \
		}                                                        \
	} while (0)

/**
 * @def TEST_ASSERT_NOT_EQUAL_GOTO(expected, actual, label)
 * @brief Assert that @p expected != @p actual; set @c test_status and goto @p label on failure.
 *
 * @param expected Value that @p actual must not equal.
 * @param actual   Actual integer value.
 * @param label    Label to jump to on failure.
 */
#define TEST_ASSERT_NOT_EQUAL_GOTO(expected, actual, label)         \
	do {                                                        \
		if ((expected) == (actual)) {                       \
			TEST_PRINT_FAIL("Expected not equal to %d", \
					(int)(expected));           \
			test_status = false;                        \
			goto label;                                 \
		}                                                   \
	} while (0)

/**
 * @def TEST_ASSERT_NULL_GOTO(ptr, label)
 * @brief Assert that @p ptr is @c NULL; set @c test_status and goto @p label on failure.
 *
 * @param ptr   Pointer to check.
 * @param label Label to jump to on failure.
 */
#define TEST_ASSERT_NULL_GOTO(ptr, label)                         \
	do {                                                      \
		if ((ptr) != NULL) {                              \
			TEST_PRINT_FAIL("Expected NULL pointer"); \
			test_status = false;                      \
			goto label;                               \
		}                                                 \
	} while (0)

/**
 * @def TEST_ASSERT_NOT_NULL_GOTO(ptr, label)
 * @brief Assert that @p ptr is not @c NULL; set @c test_status and goto @p label on failure.
 *
 * @param ptr   Pointer to check.
 * @param label Label to jump to on failure.
 */
#define TEST_ASSERT_NOT_NULL_GOTO(ptr, label)                         \
	do {                                                          \
		if ((ptr) == NULL) {                                  \
			TEST_PRINT_FAIL("Expected non-NULL pointer"); \
			test_status = false;                          \
			goto label;                                   \
		}                                                     \
	} while (0)

/**
 * @def TEST_ASSERT_PTR_EQUAL_GOTO(expected, actual, label)
 * @brief Assert that pointers @p expected and @p actual are equal;
 *        set @c test_status and goto @p label on failure.
 *
 * @param expected Expected pointer value.
 * @param actual   Actual pointer value.
 * @param label    Label to jump to on failure.
 */
#define TEST_ASSERT_PTR_EQUAL_GOTO(expected, actual, label)                    \
	do {                                                                   \
		if ((expected) != (actual)) {                                  \
			TEST_PRINT_FAIL("Expected pointer %p, got %p",         \
					(void *)(expected), (void *)(actual)); \
			test_status = false;                                   \
			goto label;                                            \
		}                                                              \
	} while (0)

/**
 * @def TEST_ASSERT_STRING_EQUAL_GOTO(expected, actual, label)
 * @brief Assert that strings @p expected and @p actual are equal;
 *        set @c test_status and goto @p label on failure.
 *
 * @param expected Expected C string.
 * @param actual   Actual C string.
 * @param label    Label to jump to on failure.
 */
#define TEST_ASSERT_STRING_EQUAL_GOTO(expected, actual, label)         \
	do {                                                           \
		if (strcmp((expected), (actual)) != 0) {               \
			TEST_PRINT_FAIL("Expected \"%s\", got \"%s\"", \
					(expected), (actual));         \
			test_status = false;                           \
			goto label;                                    \
		}                                                      \
	} while (0)

/**
 * @def TEST_ASSERT_MEMORY_EQUAL_GOTO(expected, actual, size, label)
 * @brief Assert that two memory regions are equal;
 *        set @c test_status and goto @p label on failure.
 *
 * @param expected Pointer to expected memory region.
 * @param actual   Pointer to actual memory region.
 * @param size     Number of bytes to compare.
 * @param label    Label to jump to on failure.
 */
#define TEST_ASSERT_MEMORY_EQUAL_GOTO(expected, actual, size, label) \
	do {                                                         \
		if (memcmp((expected), (actual), (size)) != 0) {     \
			TEST_PRINT_FAIL("Memory comparison failed"); \
			test_status = false;                         \
			goto label;                                  \
		}                                                    \
	} while (0)

/**
 * @def TEST_ASSERT_CONTINUE(condition)
 * @brief Assert that @p condition is true; set @c test_status on failure and continue.
 *
 * @param condition Expression to evaluate.
 */
#define TEST_ASSERT_CONTINUE(condition)                                      \
	do {                                                                 \
		if (!(condition)) {                                          \
			TEST_PRINT_FAIL("Assertion failed: %s", #condition); \
			test_status = false;                                 \
		}                                                            \
	} while (0)

/**
 * @def TEST_ASSERT_EQUAL_CONTINUE(expected, actual)
 * @brief Assert that @p expected == @p actual; set @c test_status on failure and continue.
 *
 * @param expected Expected integer value.
 * @param actual   Actual integer value.
 */
#define TEST_ASSERT_EQUAL_CONTINUE(expected, actual)                     \
	do {                                                             \
		if ((expected) != (actual)) {                            \
			TEST_PRINT_FAIL("Expected %d, got %d",           \
					(int)(expected), (int)(actual)); \
			test_status = false;                             \
		}                                                        \
	} while (0)

/**
 * @def TEST_ASSERT_NOT_EQUAL_CONTINUE(expected, actual)
 * @brief Assert that @p expected != @p actual; set @c test_status on failure and continue.
 *
 * @param expected Value that @p actual must not equal.
 * @param actual   Actual integer value.
 */
#define TEST_ASSERT_NOT_EQUAL_CONTINUE(expected, actual)            \
	do {                                                        \
		if ((expected) == (actual)) {                       \
			TEST_PRINT_FAIL("Expected not equal to %d", \
					(int)(expected));           \
			test_status = false;                        \
		}                                                   \
	} while (0)

/**
 * @def TEST_ASSERT_NULL_CONTINUE(ptr)
 * @brief Assert that @p ptr is @c NULL; set @c test_status on failure and continue.
 *
 * @param ptr Pointer to check.
 */
#define TEST_ASSERT_NULL_CONTINUE(ptr)                            \
	do {                                                      \
		if ((ptr) != NULL) {                              \
			TEST_PRINT_FAIL("Expected NULL pointer"); \
			test_status = false;                      \
		}                                                 \
	} while (0)

/**
 * @def TEST_ASSERT_NOT_NULL_CONTINUE(ptr)
 * @brief Assert that @p ptr is not @c NULL; set @c test_status on failure and continue.
 *
 * @param ptr Pointer to check.
 */
#define TEST_ASSERT_NOT_NULL_CONTINUE(ptr)                            \
	do {                                                          \
		if ((ptr) == NULL) {                                  \
			TEST_PRINT_FAIL("Expected non-NULL pointer"); \
			test_status = false;                          \
		}                                                     \
	} while (0)

/**
 * @def TEST_ASSERT_PTR_EQUAL_CONTINUE(expected, actual)
 * @brief Assert that pointers @p expected and @p actual are equal;
 *        set @c test_status on failure and continue.
 *
 * @param expected Expected pointer value.
 * @param actual   Actual pointer value.
 */

#define TEST_ASSERT_PTR_EQUAL_CONTINUE(expected, actual)                       \
	do {                                                                   \
		if ((expected) != (actual)) {                                  \
			TEST_PRINT_FAIL("Expected pointer %p, got %p",         \
					(void *)(expected), (void *)(actual)); \
			test_status = false;                                   \
		}                                                              \
	} while (0)

/**
 * @def TEST_ASSERT_STRING_EQUAL_CONTINUE(expected, actual)
 * @brief Assert that strings @p expected and @p actual are equal;
 *        set @c test_status on failure and continue.
 *
 * @param expected Expected C string.
 * @param actual   Actual C string.
 */
#define TEST_ASSERT_STRING_EQUAL_CONTINUE(expected, actual)            \
	do {                                                           \
		if (strcmp((expected), (actual)) != 0) {               \
			TEST_PRINT_FAIL("Expected \"%s\", got \"%s\"", \
					(expected), (actual));         \
			test_status = false;                           \
		}                                                      \
	} while (0)

/**
 * @def TEST_ASSERT_MEMORY_EQUAL_CONTINUE(expected, actual, size)
 * @brief Assert that two memory regions are equal;
 *        set @c test_status on failure and continue.
 *
 * @param expected Pointer to expected memory region.
 * @param actual   Pointer to actual memory region.
 * @param size     Number of bytes to compare.
 */
#define TEST_ASSERT_MEMORY_EQUAL_CONTINUE(expected, actual, size)    \
	do {                                                         \
		if (memcmp((expected), (actual), (size)) != 0) {     \
			TEST_PRINT_FAIL("Memory comparison failed"); \
			test_status = false;                         \
		}                                                    \
	} while (0)

/**
 * @typedef test_func_t
 * @brief Prototype for a test function.
 *
 * @param params Optional parameters passed at registration time (may be @c NULL).
 * @return @c true if the test passed, @c false otherwise.
 */
typedef bool (*test_func_t)(void *params);

/**
 * @typedef test_setup_func_t
 * @brief Prototype for a suite setup function.
 *
 * Called once before the first test in the suite runs.
 *
 * @param params Optional parameters (may be @c NULL).
 */
typedef void (*test_setup_func_t)(void *params);

/**
 * @typedef test_teardown_func_t
 * @brief Prototype for a suite teardown function.
 *
 * Called once after the last test in the suite completes.
 *
 * @param params Optional parameters (may be @c NULL).
 */
typedef void (*test_teardown_func_t)(void *params);

/**
 * @brief Initialize the test framework.
 *
 * Must be called before registering any tests or setting up suite
 * setup/teardown functions.
 */
void test_framework_init(void);

/**
 * @brief Set the suite-level setup function.
 *
 * The setup function is called once before the first test in the suite runs.
 * Pass @c NULL for @p setup to disable suite setup.
 *
 * @param setup  Function to call before running any tests (may be @c NULL).
 * @param params Optional parameters to pass to @p setup (may be @c NULL).
 */
void test_framework_set_suite_setup(test_setup_func_t setup, void *params);

/**
 * @brief Set the suite-level teardown function.
 *
 * The teardown function is called once after all tests in the suite have run.
 * Pass @c NULL for @p teardown to disable suite teardown.
 *
 * @param teardown Function to call after all tests complete (may be @c NULL).
 * @param params   Optional parameters to pass to @p teardown (may be @c NULL).
 */
void test_framework_set_suite_teardown(test_teardown_func_t teardown,
				       void *params);

/**
 * @brief Register a test function.
 *
 * Registers a test function to be executed by test_framework_run().
 *
 * @param name   Human-readable name of the test (used in output).
 * @param func   Test function to execute.
 * @param params Optional parameters to pass to @p func (may be @c NULL).
 */
void test_framework_register(const char *name, test_func_t func, void *params);

/**
 * @brief Run all registered tests.
 *
 * Executes all registered test functions in registration order, calls the
 * suite setup before the first test and the suite teardown after the last
 * test, and prints a result summary.
 *
 * @return @c 0 if all tests passed, @c 1 if any test failed.
 */
int test_framework_run(void);

/**
 * @def TEST_REGISTER(func)
 * @brief Register a test function without parameters.
 *
 * Uses the stringified function name as the test name.
 *
 * @param func Test function name.
 */
#define TEST_REGISTER(func) test_framework_register(#func, func, NULL)

/**
 * @def TEST_REGISTER_WITH_PARAMS(func, params)
 * @brief Register a test function with parameters.
 *
 * Uses the stringified function name as the test name.
 *
 * @param func   Test function name.
 * @param params Parameters to pass to the test function.
 */
#define TEST_REGISTER_WITH_PARAMS(func, params) \
	test_framework_register(#func, func, params)

/**
 * @def TEST_SET_SUITE_SETUP(func)
 * @brief Set the suite setup function without parameters.
 *
 * @param func Setup function name.
 */
#define TEST_SET_SUITE_SETUP(func) test_framework_set_suite_setup(func, NULL)

/**
 * @def TEST_SET_SUITE_SETUP_WITH_PARAMS(func, params)
 * @brief Set the suite setup function with parameters.
 *
 * @param func   Setup function name.
 * @param params Parameters to pass to the setup function.
 */
#define TEST_SET_SUITE_SETUP_WITH_PARAMS(func, params) \
	test_framework_set_suite_setup(func, params)

/**
 * @def TEST_SET_SUITE_TEARDOWN(func)
 * @brief Set the suite teardown function without parameters.
 *
 * @param func Teardown function name.
 */
#define TEST_SET_SUITE_TEARDOWN(func) \
	test_framework_set_suite_teardown(func, NULL)

/**
 * @def TEST_SET_SUITE_TEARDOWN_WITH_PARAMS(func, params)
 * @brief Set the suite teardown function with parameters.
 *
 * @param func   Teardown function name.
 * @param params Parameters to pass to the teardown function.
 */
#define TEST_SET_SUITE_TEARDOWN_WITH_PARAMS(func, params) \
	test_framework_set_suite_teardown(func, params)

/** @} */ /* end of test_framework */

#endif /* __TEST_FRAMEWORK_H__ */
