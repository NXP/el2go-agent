/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef TEST_EL2GO_OTA_FIXTURES_H
#define TEST_EL2GO_OTA_FIXTURES_H

#include <stddef.h>
#include <stdint.h>

#include "common/el2go_platform.h"
#include "common/el2go_status.h"
#include "ota/el2go_ota_config.h"
#include "ota/el2go_ota_lib.h"

/**
 * @brief Build a minimal, valid mTLS config pointing at a dummy CA chain.
 */
el2go_ota_mtls_config_t ota_fixture_make_cfg(void);

/**
 * @brief Lazily-initialised shared platform context for tests that
 *        need a non-NULL el2go_platform_ctx_t
 */
el2go_platform_ctx_t *ota_fixture_get_pctx(void);

/**
 * @brief Reset the net_crypto wrap control variables to their default state.
 */
void ota_fixture_reset_net_crypto_wraps(void);

/**
 * @brief Reset every net_crypto and psa_its_ wrap control variable
 *        to their default state.
 */
void ota_fixture_reset_net_crypto_and_psa_wraps(void);

/**
 * @brief No-op download chunk callback; satisfies the non-NULL callback requirement
 */
el2go_ota_status_t ota_fixture_noop_chunk_cb(const uint8_t *data, size_t len, size_t offset,
                                             void *ctx);

/**
 * @brief Reset the net_crypto wraps and bring up a library context that is
 *        initialised and connected, using ota_fixture_make_cfg().
 *
 * @param[out] ctx  Receives the context; the caller owns it (el2go_ota_cleanup()).
 *
 * @note The config is a single static instance shared by every context created
 *       through this helper. Do not hold two such contexts at the same time.
 * @return true if init and connect both succeeded.
 */
bool ota_fixture_init_connected(el2go_ota_ctx_t **ctx);

#endif /* TEST_EL2GO_OTA_FIXTURES_H */
