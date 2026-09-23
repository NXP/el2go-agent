/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <zephyr/ztest.h>

#include "test_ztest.h"

#include "test_fwual_internal.h"
#include "test_fwual_public.h"

ZTEST_SUITE(fwual_ct, NULL, NULL, NULL, NULL, NULL);

TEST_ZTEST_SUITE(fwual_ct, fwual_internal)
TEST_ZTEST_SUITE(fwual_ct, fwual_public)
