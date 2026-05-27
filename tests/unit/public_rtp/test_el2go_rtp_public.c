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
	el2go_status_t status = EL2GO_STATUS_SUCCESS;
	bool test_status = true;

	(void)params;

	status = el2go_rtp_init(&ctx);
	TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
	TEST_ASSERT_NOT_NULL_GOTO(ctx, exit);

	status = el2go_rtp_free(&ctx);
	TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
	TEST_ASSERT_NULL_CONTINUE(ctx);

exit:
	return test_status;
}

static bool test_el2go_rtp_null_parameters(void *params)
{
	el2go_status_t status = EL2GO_STATUS_SUCCESS;

	(void)params;

	status = el2go_rtp_init(NULL);
	TEST_ASSERT_EQUAL(EL2GO_STATUS_INVALID_POINTER, status);

	status = el2go_rtp_free(NULL);
	TEST_ASSERT_EQUAL(EL2GO_STATUS_INVALID_POINTER, status);

	return true;
}

void register_el2go_rtp_tests(void)
{
	TEST_REGISTER(test_el2go_rtp_init_and_free);
	TEST_REGISTER(test_el2go_rtp_null_parameters);
}
