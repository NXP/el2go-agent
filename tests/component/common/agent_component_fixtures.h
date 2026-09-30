/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef AGENT_COMPONENT_FIXTURES_H
#define AGENT_COMPONENT_FIXTURES_H

#include "test_framework.h"

/* Verifies an OTA agent's public API (fwual_init(), el2go_ota_init()) is
 * reachable and links cleanly. Shared by both agents' public component
 * suites; the body is identical for both. */
test_result_t agent_ct_public_api_reachable(void);

#endif /* AGENT_COMPONENT_FIXTURES_H */
