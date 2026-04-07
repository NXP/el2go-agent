// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright 2026 NXP
 */

#include "rtp/el2go_rtp.h"
#include "test_framework.h"
#include "test_suites.h"

static bool test_el2go_rtp_init_and_free(void *params)
{
	el2go_rtp_ctx_t *ctx = NULL;

	(void)params;

	TEST_ASSERT_EQUAL(EL2GO_STATUS_SUCCESS, el2go_rtp_init(&ctx));
	TEST_ASSERT_NOT_NULL(ctx);

	TEST_ASSERT_EQUAL(EL2GO_STATUS_SUCCESS, el2go_rtp_free(&ctx));
	TEST_ASSERT_NULL(ctx);

	return true;
}

static bool test_el2go_rtp_null_parameters(void *params)
{
	(void)params;

	TEST_ASSERT_EQUAL(EL2GO_STATUS_INVALID_POINTER, el2go_rtp_init(NULL));
	TEST_ASSERT_EQUAL(EL2GO_STATUS_INVALID_POINTER, el2go_rtp_free(NULL));
	return true;
}

void register_el2go_rtp_tests(void)
{
	TEST_REGISTER(test_el2go_rtp_init_and_free);
	TEST_REGISTER(test_el2go_rtp_null_parameters);
}
