// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright 2026 NXP
 */

#include "rtp/el2go_rtp.h"
#include "test_framework.h"
#include "test_suites.h"
#include "el2go_rtp_internal.h"

/* ========================================================================== */
/* Simple Internal Test - Verify Agent Context Structure                     */
/* ========================================================================== */

static bool test_el2go_rtp_context_structure(void *params)
{
	el2go_rtp_ctx_t *ctx = NULL;
	el2go_status_t status = EL2GO_STATUS_SUCCESS;
	bool test_status = true;

	(void)params;

	status = el2go_rtp_init(&ctx);
	TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
	TEST_ASSERT_NOT_NULL_GOTO(ctx, exit);

	TEST_ASSERT_EQUAL_GOTO(0, ctx->num_keystores, cleanup);
	TEST_ASSERT_EQUAL_CONTINUE(0, ctx->num_datastores);

cleanup:
	status = el2go_rtp_free(&ctx);
	TEST_ASSERT_EQUAL_GOTO(EL2GO_STATUS_SUCCESS, status, exit);
	TEST_ASSERT_NULL(ctx);

exit:
	return test_status;
}

void register_el2go_rtp_tests(void)
{
	TEST_REGISTER(test_el2go_rtp_context_structure);
}
