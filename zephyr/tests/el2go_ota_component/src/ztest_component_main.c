/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <zephyr/ztest.h>

#include "test_ztest.h"

#include "test_el2go_ota_lib_internal.h"
#include "test_el2go_ota_lib_public.h"

ZTEST_SUITE(el2go_ct, NULL, NULL, NULL, NULL, NULL);

TEST_ZTEST_SUITE(el2go_ct, ota_lib_internal)
TEST_ZTEST_SUITE(el2go_ct, ota_lib_public)
