/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef AGENT_TEST_FIXTURES_H
#define AGENT_TEST_FIXTURES_H

#include <stddef.h>
#include <stdint.h>

#include "ota/el2go_ota_lib.h"

/* Hex-encodes the SHA-256 of payload[0..len) into out (>= 65 bytes). */
void agent_fixture_sha256_hex(const uint8_t *payload, size_t len, char *out);

/* Builds a single-package/single-file update_info_t matching payload;
 * pair with el2go_ota_lib_mock_set_payload(). */
void agent_fixture_make_update_info(el2go_ota_update_info_t *update, const uint8_t *payload,
                                    size_t len);

/* Queues a check-for-updates response reporting update as available. */
void agent_fixture_queue_update_available(const el2go_ota_update_info_t *update);

/* Queues a check-for-updates response reporting no update available. */
void agent_fixture_queue_no_update(void);

#endif /* AGENT_TEST_FIXTURES_H */
