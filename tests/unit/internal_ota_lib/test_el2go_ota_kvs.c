/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "test_el2go_ota_compat_shim.h"

#include "test_framework.h"
#include "test_suites.h"

#include <string.h>
#include <stdint.h>
#include <stddef.h>

#include "common/el2go_status.h"
#include "el2go_ota_kvs.h"

/**
 * @brief el2go_ota_kvs_write with non-NULL data that is NULL but len > 0 must
 *        return EL2GO_OTA_ERROR_INVALID_PARAM.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_kvs_write_null_data_nonzero_len(void *params)
{
    (void)params;

    /* Under the no-op KVS stub this returns INVALID_PARAM without crashing. */
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM, el2go_ota_kvs_write(1U, NULL, 4U));

    return true;
}

/**
 * @brief el2go_ota_kvs_read with NULL found pointer must return
 *        EL2GO_OTA_ERROR_INVALID_PARAM.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_kvs_read_null_found(void *params)
{
    uint8_t buf[4] = { 0 };

    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM,
                      el2go_ota_kvs_read(1U, buf, sizeof(buf), NULL));

    return true;
}

/**
 * @brief el2go_ota_kvs_read with NULL data and non-zero len must return
 *        EL2GO_OTA_ERROR_INVALID_PARAM.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_kvs_read_null_data_nonzero_len(void *params)
{
    bool found = false;

    (void)params;

    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INVALID_PARAM, el2go_ota_kvs_read(1U, NULL, 4U, &found));

    return true;
}

/**
 * @brief Verify kvs write zero len.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_kvs_write_zero_len(void *params)
{
    static const uint8_t data[4] = { 0 };
    (void)params;
    /* Zero len write must fail (exercises the len==0 guard branch). */
    TEST_ASSERT(EL2GO_OTA_SUCCESS != el2go_ota_kvs_write(1U, data, 0U));
    return true;
}

/**
 * @brief Verify kvs read zero len.
 *
 * @param params Unused.
 * @return @c true if all assertions pass, @c false otherwise.
 */
static bool test_ota_kvs_read_zero_len(void *params)
{
    bool found = true;
    (void)params;
    TEST_ASSERT_EQUAL(EL2GO_OTA_ERROR_INTERNAL, el2go_ota_kvs_read(99U, NULL, 0U, &found));
    return true;
}

/* ---- suite registration ------------------------------------------------ */

void register_ota_lib_kvs_tests(void)
{
    TEST_REGISTER_ID("11.1", test_ota_kvs_write_null_data_nonzero_len);
    TEST_REGISTER_ID("11.2", test_ota_kvs_read_null_found);
    TEST_REGISTER_ID("11.3", test_ota_kvs_read_null_data_nonzero_len);
    TEST_REGISTER_ID("11.4", test_ota_kvs_write_zero_len);
    TEST_REGISTER_ID("11.5", test_ota_kvs_read_zero_len);
}
