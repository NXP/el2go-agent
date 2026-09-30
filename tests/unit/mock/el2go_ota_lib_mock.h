/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

/**
 * @file el2go_ota_lib_mock.h
 * @brief Test-only mock for the el2go_ota_lib public API.
 */

#ifndef EL2GO_OTA_LIB_MOCK_H
#define EL2GO_OTA_LIB_MOCK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "ota/el2go_ota_lib.h"

/** @brief Reset every counter/flag/queue to its default (empty/false/zero). */
void el2go_ota_lib_mock_reset(void);

/* ---- check_for_updates() scripting ------------------------------------- */
void el2go_ota_lib_mock_queue_check_response(const el2go_ota_check_update_resp_t *resp,
                                             el2go_ota_status_t status);
size_t el2go_ota_lib_mock_check_count(void);

/* ---- download_package() scripting ------------------------------------- */
void el2go_ota_lib_mock_set_payload(const uint8_t *data, size_t len);
void el2go_ota_lib_mock_set_download_fail_count(uint32_t fail_count);
void el2go_ota_lib_mock_set_download_hard_fail(bool always_fail);
size_t el2go_ota_lib_mock_download_call_count(void);
size_t el2go_ota_lib_mock_last_resume_offset(void);

/* ---- status reporting scripting ---------------------------------------- */
void el2go_ota_lib_mock_set_report_reject_count(uint32_t reject_count);
el2go_ota_update_outcome_t el2go_ota_lib_mock_last_reported_outcome(void);
const char *el2go_ota_lib_mock_last_reported_update_id(void);
const char *el2go_ota_lib_mock_last_reported_package_id(void);
size_t el2go_ota_lib_mock_report_call_count(void);

/* ---- pending-status scripting ------------------------------------------- */
void el2go_ota_lib_mock_set_pending_status(const el2go_ota_pending_status_t *status);

/* ---- schedule_status_report() / report_pending_status() scripting ------- */
el2go_ota_update_outcome_t el2go_ota_lib_mock_last_scheduled_outcome(void);
const char *el2go_ota_lib_mock_last_scheduled_update_id(void);
const char *el2go_ota_lib_mock_last_scheduled_package_id(void);
size_t el2go_ota_lib_mock_schedule_call_count(void);

void el2go_ota_lib_mock_set_pending_reject_count(uint32_t reject_count);
size_t el2go_ota_lib_mock_pending_delivered_count(void);
size_t el2go_ota_lib_mock_report_pending_call_count(void);

/* ---- connect/init state -------------------------------------------------- */
void el2go_ota_lib_mock_set_connect_fail(bool fail);
size_t el2go_ota_lib_mock_connect_call_count(void);

/** @brief Forces el2go_ota_is_connected() to report false until the next
 * successful connect() call, simulating a dropped connection detected at
 * check time. */
void el2go_ota_lib_mock_force_disconnected(void);

#endif /* EL2GO_OTA_LIB_MOCK_H */
