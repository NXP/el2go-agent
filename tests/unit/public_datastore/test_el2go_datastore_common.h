/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef TEST_EL2GO_DATASTORE_COMMON_H
#define TEST_EL2GO_DATASTORE_COMMON_H

#include "rtp/el2go_rtp.h"
#include "common/el2go_datastore.h"

/* ========================================================================== */
/* Suite Context                                                              */
/* ========================================================================== */

typedef struct {
	el2go_rtp_ctx_t *rtp_ctx;
} suite_context_t;

/* ========================================================================== */
/* Common Test Functions                                                      */
/* ========================================================================== */

bool common_test_ds_init_and_free(el2go_datastore_type_t type, const char *name,
				  uint32_t id, const el2go_datastore_ops_t *ops,
				  void *ctx);

bool common_test_ds_full_transaction(el2go_datastore_type_t type,
				     const char *name,
				     const el2go_datastore_ops_t *ops,
				     void *ctx);

bool common_test_ds_multiple_transactions(el2go_datastore_type_t type,
					  const char *name,
					  const el2go_datastore_ops_t *ops,
					  void *ctx);

bool common_test_ds_write_at_different_offsets(el2go_datastore_type_t type,
					       const char *name,
					       const el2go_datastore_ops_t *ops,
					       void *ctx);

bool common_test_ds_write_out_of_bounds(el2go_datastore_type_t type,
					const char *name,
					const el2go_datastore_ops_t *ops,
					void *ctx,
					el2go_status_t expected_status);

bool common_test_ds_read_out_of_bounds(el2go_datastore_type_t type,
				       const char *name,
				       const el2go_datastore_ops_t *ops,
				       void *ctx,
				       el2go_status_t expected_status);

bool common_test_ds_transaction_recovery(el2go_datastore_type_t type,
					 const char *name,
					 const el2go_datastore_ops_t *ops,
					 void *ctx);

bool common_test_ds_large_allocation(el2go_datastore_type_t type,
				     const char *name,
				     const el2go_datastore_ops_t *ops,
				     void *ctx);

/* ========================================================================== */
/* Test Registration Functions                                                */
/* ========================================================================== */

void register_datastore_sanity_tests(void);
void register_datastore_fs_tests(void);
void register_datastore_plain_tests(void);
void register_datastore_custom_tests(void);

#endif /* TEST_EL2GO_DATASTORE_COMMON_H */
