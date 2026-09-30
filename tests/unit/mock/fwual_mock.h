/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

/**
 * @file fwual_mock.h
 * @brief Test-only extras exposed by fwual_mock.c beyond the real fwual.h API.
 */

#ifndef FWUAL_MOCK_H
#define FWUAL_MOCK_H

#include <stdbool.h>
#include <stddef.h>

#include "fwual/fwual.h"

/** @brief Internal per-session image buffer size used by the mock. */
#define FWUAL_MOCK_IMAGE_BUF_SIZE 4096U

/** @brief Returns the cancelled flag for the given image, if found in the
 * current session's image list. Returns false if not found. */
bool fwual_mock_image_cancelled(fwual_image_id_t image_id);

/** @brief Directly assigns the mock's internal lifecycle state, bypassing
 * normal transition logic. Simulates "the device just rebooted into this
 * FWUAL state." */
void fwual_mock_set_lifecycle_state_for_test(fwual_state_t state);

/** @brief One-shot flag: the next call to fwual_prepare_image() returns
 * FWUAL_ERR_INTERNAL immediately, before any other logic runs, then the
 * flag clears itself. */
void fwual_mock_set_prepare_fail_for_test(bool fail_next);

/** @brief One-shot flag: the next call to fwual_check_storage() returns
 * FWUAL_ERR_NO_SPACE immediately, before any other logic runs, then the
 * flag clears itself. */
void fwual_mock_set_check_storage_fail_for_test(bool fail_next);

/** @brief Resets the mock to its uninitialized state, simulating a reboot. */
void fwual_mock_simulate_reboot(void);

#endif /* FWUAL_MOCK_H */
