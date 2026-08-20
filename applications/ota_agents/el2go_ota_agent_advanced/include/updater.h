/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

/* Updater: the core OTA flow for the advanced sample. */

#ifndef __UPDATER_H__
#define __UPDATER_H__

#include "ota/el2go_ota_lib.h"
#include "fwual/fwual.h"

/** @brief Updater context shared across the advanced sample. */
typedef struct {
    el2go_ota_ctx_t *ota_ctx; /**< EL2GO OTA library context */
    fwual_caps_t fwual_caps;  /**< Cached FWUAL backend capabilities */
} updater_ctx_t;

/**
 * @brief Runs one full OTA check cycle
 *
 * Performs the sequence reconnect, check, policy evaluation, download and
 * handoff, status report, and reboot. On any recoverable failure the scheduler
 * is asked to back off; on success the device reboots to apply the update.
 *
 * @param[in] updater Updater context
 */
void updater_run_check(updater_ctx_t *updater);

/**
 * @brief Reconciles persisted state against FWUAL after boot
 *
 * Call exactly once, after el2go_ota_connect() succeeds but before the
 * scheduler is started. Depending on fw_state it confirms a freshly validated
 * image, reports SUCCESS, FAILURE or ROLLBACK to the server, and clears the
 * persisted record as appropriate.
 *
 * @param[in] updater  Updater context
 * @param[in] fw_state FWUAL state captured early on boot via fwual_get_state()
 */
void updater_finalize_boot(updater_ctx_t *updater, fwual_state_t fw_state);

#endif /* __UPDATER_H__ */
