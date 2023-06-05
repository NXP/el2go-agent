/*
 * Copyright 2023 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef __EL2GO_BLOB_TEST_H__
#define __EL2GO_BLOB_TEST_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "fsl_debug_console.h"
#include "board.h"

enum serial_color_t {
    DEFAULT = 0,
    RED     = 31,
    GREEN   = 32,
    YELLOW  = 33,
    BLUE    = 34,
    MAGENTA = 35,
    CYAN    = 36
};

#define PRINTF_SET_COLOR(color) PRINTF("\33[%dm", color)

enum test_status_t {
    TEST_PASSED = 0,
    TEST_FAILED = 1,
    TEST_SKIPPED = 2,
};

struct test_result_t {
    enum test_status_t status;
    const char *message;
    const char *function;
    uint32_t line;
};

typedef void TESTCASE(struct test_result_t *result);
struct test_t {
    TESTCASE * const testcase;
    const char *name;
    const char *description;
};

struct test_suite_t;
typedef void TESTSUITE(struct test_suite_t *test_suite);
struct test_suite_t {
    TESTSUITE * const suite;
    struct test_t *test_list;
    uint32_t test_list_size;
    const char *name;
    enum test_status_t status;
};

void testsuite_blob_internal(struct test_suite_t *test_suite);
void testsuite_blob_external(struct test_suite_t *test_suite);

#ifdef __cplusplus
}
#endif

#endif /* __EL2GO_BLOB_TEST_H__ */
