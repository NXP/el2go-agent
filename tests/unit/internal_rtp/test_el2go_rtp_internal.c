// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright 2026 NXP
 */

#include "test_framework.h"
#include "test_suites.h"
#include "el2go_agent.h"
#include "el2go_agent_internal.h"

/* ========================================================================== */
/* Simple Internal Test - Verify Agent Context Structure                     */
/* ========================================================================== */

static bool test_el2go_rtp_context_structure(void *params)
{
	el2go_agent_ctx_t *ctx = NULL;

	/* params can be used if needed, otherwise ignore */
	(void)params;

	/* Initialize agent */
	TEST_ASSERT_EQUAL(EL2GO_AGENT_SUCCESS, el2go_agent_init(&ctx));
	TEST_ASSERT_NOT_NULL(ctx);
	TEST_ASSERT_EQUAL(0, ctx->num_keystores);
	TEST_ASSERT_EQUAL(0, ctx->num_datastores);
	TEST_ASSERT_NOT_NULL(ctx);

	/* Clean up */
	TEST_ASSERT_EQUAL(EL2GO_AGENT_SUCCESS, el2go_agent_free(&ctx));
	TEST_ASSERT_NULL(ctx);

	return true;
}

void register_el2go_rtp_tests(void)
{
	TEST_REGISTER(test_el2go_rtp_context_structure);
}
