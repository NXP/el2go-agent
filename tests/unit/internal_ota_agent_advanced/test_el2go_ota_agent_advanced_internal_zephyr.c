/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

/*
 * Internal ota_agent_advanced unit tests: direct calls into
 * policy_evaluate()/scheduler_*(), plus updater_run_check() branch coverage
 * against the fully mocked el2go_ota_lib/fwual/app-sys seams.
 */

#include "test_suites.h"

#include <string.h>
#include <psa/crypto.h>

#include "test_framework.h"

#include "updater.h"
#include "policy.h"
#include "scheduler.h"
#include "agent_test_fixtures.h"
#include "el2go_ota_lib_mock.h"
#include "fwual_mock.h"
#include "wrap_app_sys.h"
#include "fwual/fwual.h"
#include "ota/el2go_ota_lib.h"
#include "el2go_ota_persist.h"

static const uint8_t k_dummy_ca_chain[] = { 0x30, 0x00 };

static updater_ctx_t build_test_updater(void)
{
    updater_ctx_t updater = { 0 };

    (void)fwual_init();
    (void)fwual_get_caps(&updater.fwual_caps);

    static const el2go_ota_mtls_config_t config = {
        .hostname = "test.local",
        .port = 443U,
        .server_ca_chain = k_dummy_ca_chain,
        .server_ca_chain_size = sizeof(k_dummy_ca_chain),
        .client_key_object_id = 0U,
        .client_cert_object_id = 0U,
        .client_auth = EL2GO_OTA_CLIENT_AUTH_NONE,
    };

    (void)el2go_ota_init(&updater.ota_ctx, &config);
    (void)el2go_ota_connect(updater.ota_ctx);

    return updater;
}

static int64_t s_epoch_ms;

static void reset_all(void)
{
    el2go_ota_lib_mock_reset();
    wrap_app_sys_reset();
    s_epoch_ms += 7LL * 24LL * 3600LL * 1000LL; /* +1 week, strictly increasing */
    wrap_app_sys_set_uptime_ms(s_epoch_ms);
    scheduler_configure(NULL, NULL);
    scheduler_reset();
    (void)fwual_init();
}

/** No update available (or NULL resp) -> POLICY_CANCEL. */
static bool test_aa_policy_cancel_no_update(void *params)
{
    (void)params;
    reset_all();

    el2go_ota_check_update_resp_t resp = { 0 };
    resp.update_available = false;
    TEST_ASSERT_EQUAL(POLICY_CANCEL, policy_evaluate(&resp));

    resp.update_available = true;
    resp.update_count = 0U;
    TEST_ASSERT_EQUAL(POLICY_CANCEL, policy_evaluate(&resp));

    TEST_ASSERT_EQUAL(POLICY_CANCEL, policy_evaluate(NULL));

    return true;
}

/** Blackout window wraparound (start > end, e.g. 22->6): hours inside vs.
 * outside the wrapped window. Config: BLACKOUT_START=22, END=6. */
static bool test_aa_policy_blackout_wraparound(void *params)
{
    (void)params;
    reset_all();

    el2go_ota_check_update_resp_t resp = { 0 };
    resp.update_available = true;
    resp.update_count = 1U;

    wrap_app_sys_set_hour_of_day(23); /* inside: hour >= start */
    TEST_ASSERT_EQUAL(POLICY_BLACKOUT, policy_evaluate(&resp));

    wrap_app_sys_set_hour_of_day(3); /* inside: hour < end */
    TEST_ASSERT_EQUAL(POLICY_BLACKOUT, policy_evaluate(&resp));

    wrap_app_sys_set_hour_of_day(12); /* outside the wrapped window */
    TEST_ASSERT_EQUAL(POLICY_PROCEED, policy_evaluate(&resp));

    return true;
}

/** Unknown wall-clock hour (-1, the wrap_app_sys default) is never
 * treated as blackout, even at an hour that would otherwise match. */
static bool test_aa_policy_blackout_unknown_hour(void *params)
{
    (void)params;
    reset_all();

    el2go_ota_check_update_resp_t resp = { 0 };
    resp.update_available = true;
    resp.update_count = 1U;

    /* wrap_app_sys_reset() (via reset_all()) already defaults hour to -1. */
    TEST_ASSERT_EQUAL(POLICY_PROCEED, policy_evaluate(&resp));

    return true;
}

/** Defer window boundary: just after policy_record_attempt(), DEFER; once
 * the configured window (30s) has elapsed, PROCEED again.
 *
 */
static bool test_aa_policy_defer_boundary(void *params)
{
    (void)params;
    reset_all();

    el2go_ota_check_update_resp_t resp = { 0 };
    resp.update_available = true;
    resp.update_count = 1U;

    wrap_app_sys_advance_ms(1); /* avoid the uptime==0 "never attempted" sentinel */
    policy_record_attempt();

    TEST_ASSERT_EQUAL(POLICY_DEFER, policy_evaluate(&resp));

    wrap_app_sys_advance_ms(((int64_t)CONFIG_EL2GO_OTA_ADV_DEFER_WINDOW_S * 1000) - 1);
    TEST_ASSERT_EQUAL(POLICY_DEFER, policy_evaluate(&resp));

    wrap_app_sys_advance_ms(2); /* now past the window */
    TEST_ASSERT_EQUAL(POLICY_PROCEED, policy_evaluate(&resp));

    return true;
}

static bool test_aa_scheduler_backoff_caps(void *params)
{
    (void)params;
    reset_all();

    uint32_t max_ms = (uint32_t)CONFIG_EL2GO_OTA_ADV_RETRY_MAX_BACKOFF_S * 1000U;

    for (int i = 0; i < 10; i++) {
        scheduler_backoff();
        uint32_t cur = scheduler_current_delay_ms();
        TEST_ASSERT(cur > 0U);
        TEST_ASSERT(cur <= max_ms);
    }
    TEST_ASSERT_EQUAL((int)max_ms, (int)scheduler_current_delay_ms());

    return true;
}

/** scheduler_reset() restores the base poll interval after backoff. */
static bool test_aa_scheduler_reset_restores_interval(void *params)
{
    (void)params;
    reset_all();

    uint32_t base_ms = (uint32_t)CONFIG_EL2GO_OTA_ADV_POLL_INTERVAL_S * 1000U;

    scheduler_backoff();
    scheduler_backoff();
    TEST_ASSERT(scheduler_current_delay_ms() != base_ms);

    scheduler_reset();
    TEST_ASSERT_EQUAL((int)base_ms, (int)scheduler_current_delay_ms());

    return true;
}

/** scheduler_rearm_ms() overrides exactly the next current_delay_ms()
 * reading. */
static bool test_aa_scheduler_rearm_overrides_delay(void *params)
{
    (void)params;
    reset_all();

    scheduler_rearm_ms(12345U);
    TEST_ASSERT_EQUAL(12345, (int)scheduler_current_delay_ms());

    return true;
}

static int s_step_cb_call_count;

static void step_cb_trampoline(void *user_data)
{
    (void)user_data;
    s_step_cb_call_count++;
}

/** scheduler_step() waits until the absolute target time, invokes the
 * registered check callback exactly once, then re-arms for the next
 * interval using the current delay. */
static bool test_aa_scheduler_step_invokes_callback(void *params)
{
    (void)params;
    reset_all();

    s_step_cb_call_count = 0;
    scheduler_configure(step_cb_trampoline, NULL);

    uint32_t base_ms = (uint32_t)CONFIG_EL2GO_OTA_ADV_POLL_INTERVAL_S * 1000U;

    scheduler_step();
    TEST_ASSERT_EQUAL(1, s_step_cb_call_count);
    /* First step's target was armed at "now" (uptime 0), so the wait is 0. */
    TEST_ASSERT_EQUAL(0, (int)wrap_app_sys_last_wait_ms());

    scheduler_step();
    TEST_ASSERT_EQUAL(2, s_step_cb_call_count);
    /* Second step waits the full poll interval to reach the next target. */
    TEST_ASSERT_EQUAL((int)base_ms, (int)wrap_app_sys_last_wait_ms());

    return true;
}

/** Checksum too short -> download/handoff fails, FAILURE reported. */
static bool test_aa_checksum_too_short(void *params)
{
    (void)params;
    reset_all();

    updater_ctx_t updater = build_test_updater();
    TEST_ASSERT_NOT_NULL(updater.ota_ctx);

    const uint8_t payload[16] = { 0 };
    el2go_ota_lib_mock_set_payload(payload, sizeof(payload));

    el2go_ota_update_info_t update;
    agent_fixture_make_update_info(&update, payload, sizeof(payload));
    update.packages[0].files[0].checksum[10] = '\0';

    agent_fixture_queue_update_available(&update);

    updater_run_check(&updater);

    TEST_ASSERT_EQUAL(EL2GO_OTA_OUTCOME_FAILURE, el2go_ota_lib_mock_last_reported_outcome());
    return true;
}

/** Unsupported checksum algorithm -> FAILURE, no download attempted. */
static bool test_aa_checksum_alg_unsupported(void *params)
{
    (void)params;
    reset_all();

    updater_ctx_t updater = build_test_updater();
    TEST_ASSERT_NOT_NULL(updater.ota_ctx);

    const uint8_t payload[16] = { 0 };
    el2go_ota_lib_mock_set_payload(payload, sizeof(payload));

    el2go_ota_update_info_t update;
    agent_fixture_make_update_info(&update, payload, sizeof(payload));
    update.packages[0].files[0].checksum_algorithm = 0x1234;

    agent_fixture_queue_update_available(&update);

    updater_run_check(&updater);

    TEST_ASSERT_EQUAL(EL2GO_OTA_OUTCOME_FAILURE, el2go_ota_lib_mock_last_reported_outcome());
    TEST_ASSERT_EQUAL(0U, (unsigned)el2go_ota_lib_mock_download_call_count());
    return true;
}

/** fwual_prepare_image() fails -> FAILURE reported. */
static bool test_aa_prepare_image_failure(void *params)
{
    (void)params;
    reset_all();

    updater_ctx_t updater = build_test_updater();
    TEST_ASSERT_NOT_NULL(updater.ota_ctx);

    uint8_t payload[16] = { 0 };
    el2go_ota_lib_mock_set_payload(payload, sizeof(payload));

    el2go_ota_update_info_t update;
    agent_fixture_make_update_info(&update, payload, sizeof(payload));
    agent_fixture_queue_update_available(&update);

    fwual_mock_set_prepare_fail_for_test(true);

    updater_run_check(&updater);

    TEST_ASSERT_EQUAL(EL2GO_OTA_OUTCOME_FAILURE, el2go_ota_lib_mock_last_reported_outcome());
    return true;
}

/** Chunk larger than fwual_caps.max_write_size -> chunk_cb() rejects it */
static bool test_aa_chunk_exceeds_max_write_size(void *params)
{
    (void)params;
    reset_all();

    updater_ctx_t updater = build_test_updater();
    TEST_ASSERT_NOT_NULL(updater.ota_ctx);

    updater.fwual_caps.max_write_size = 8U;

    uint8_t payload[64];
    memset(payload, 0xAB, sizeof(payload));
    el2go_ota_lib_mock_set_payload(payload, sizeof(payload));

    el2go_ota_update_info_t update;
    agent_fixture_make_update_info(&update, payload, sizeof(payload));
    agent_fixture_queue_update_available(&update);

    updater_run_check(&updater);

    TEST_ASSERT_EQUAL(EL2GO_OTA_OUTCOME_FAILURE, el2go_ota_lib_mock_last_reported_outcome());
    TEST_ASSERT_EQUAL((int)CONFIG_EL2GO_OTA_ADV_DOWNLOAD_MAX_RETRIES,
                      (int)el2go_ota_lib_mock_download_call_count());
    return true;
}

/** No update available -> updater_run_check() calls scheduler_reset()
 * (POLICY_CANCEL path) and returns without downloading or reporting. */
static bool test_aa_no_update_calls_scheduler_reset(void *params)
{
    (void)params;
    reset_all();

    updater_ctx_t updater = build_test_updater();
    TEST_ASSERT_NOT_NULL(updater.ota_ctx);

    scheduler_backoff(); /* perturb the delay so scheduler_reset()'s effect is observable */
    uint32_t base_ms = (uint32_t)CONFIG_EL2GO_OTA_ADV_POLL_INTERVAL_S * 1000U;
    TEST_ASSERT(scheduler_current_delay_ms() != base_ms);

    agent_fixture_queue_no_update();

    updater_run_check(&updater);

    TEST_ASSERT_EQUAL(1U, (unsigned)el2go_ota_lib_mock_check_count());
    TEST_ASSERT_EQUAL(0U, (unsigned)el2go_ota_lib_mock_download_call_count());
    TEST_ASSERT_EQUAL((int)base_ms, (int)scheduler_current_delay_ms());
    return true;
}

/** Malformed checksum hex (non-hex char) -> sscanf() fails -> FAILURE. */
static bool test_aa_checksum_malformed_hex(void *params)
{
    (void)params;
    reset_all();

    updater_ctx_t updater = build_test_updater();
    TEST_ASSERT_NOT_NULL(updater.ota_ctx);

    const uint8_t payload[16] = { 0 };
    el2go_ota_lib_mock_set_payload(payload, sizeof(payload));

    el2go_ota_update_info_t update;
    agent_fixture_make_update_info(&update, payload, sizeof(payload));
    /* Overwrite with a non-hex character; checksum stays 64 chars long. */
    update.packages[0].files[0].checksum[0] = 'z';
    update.packages[0].files[0].checksum[1] = 'z';

    agent_fixture_queue_update_available(&update);

    updater_run_check(&updater);

    TEST_ASSERT_EQUAL(EL2GO_OTA_OUTCOME_FAILURE, el2go_ota_lib_mock_last_reported_outcome());
    TEST_ASSERT_EQUAL(0U, (unsigned)el2go_ota_lib_mock_download_call_count());
    return true;
}

/** fwual_check_storage() reports FWUAL_ERR_NO_SPACE -> FAILURE reported,
 * no download attempted. */
static bool test_aa_check_storage_no_space(void *params)
{
    (void)params;
    reset_all();

    updater_ctx_t updater = build_test_updater();
    TEST_ASSERT_NOT_NULL(updater.ota_ctx);

    uint8_t payload[16] = { 0 };
    el2go_ota_lib_mock_set_payload(payload, sizeof(payload));

    el2go_ota_update_info_t update;
    agent_fixture_make_update_info(&update, payload, sizeof(payload));
    agent_fixture_queue_update_available(&update);

    fwual_mock_set_check_storage_fail_for_test(true);

    updater_run_check(&updater);

    TEST_ASSERT_EQUAL(EL2GO_OTA_OUTCOME_FAILURE, el2go_ota_lib_mock_last_reported_outcome());
    TEST_ASSERT_EQUAL(0U, (unsigned)el2go_ota_lib_mock_download_call_count());
    return true;
}

/** el2go_ota_check_for_updates() itself fails -> scheduler_backoff(),
 * no policy evaluation / download attempted. */
static bool test_aa_check_for_updates_failure_backs_off(void *params)
{
    (void)params;
    reset_all();

    updater_ctx_t updater = build_test_updater();
    TEST_ASSERT_NOT_NULL(updater.ota_ctx);

    el2go_ota_check_update_resp_t resp = { 0 };
    el2go_ota_lib_mock_queue_check_response(&resp, EL2GO_OTA_ERROR_NETWORK);

    uint32_t base_ms = (uint32_t)CONFIG_EL2GO_OTA_ADV_POLL_INTERVAL_S * 1000U;

    updater_run_check(&updater);

    TEST_ASSERT_EQUAL(0U, (unsigned)el2go_ota_lib_mock_download_call_count());
    TEST_ASSERT(scheduler_current_delay_ms() != base_ms);
    return true;
}

/** Defer window active (policy_record_attempt() just called) ->
 * updater_run_check() rearms via scheduler_rearm_ms() and returns without
 * downloading. */
static bool test_aa_run_check_policy_defer(void *params)
{
    (void)params;
    reset_all();

    updater_ctx_t updater = build_test_updater();
    TEST_ASSERT_NOT_NULL(updater.ota_ctx);

    wrap_app_sys_advance_ms(1); /* avoid uptime==0 "never attempted" sentinel */
    policy_record_attempt();

    uint8_t payload[16] = { 0 };
    el2go_ota_lib_mock_set_payload(payload, sizeof(payload));
    el2go_ota_update_info_t update;
    agent_fixture_make_update_info(&update, payload, sizeof(payload));
    agent_fixture_queue_update_available(&update);

    updater_run_check(&updater);

    TEST_ASSERT_EQUAL(0U, (unsigned)el2go_ota_lib_mock_download_call_count());
    TEST_ASSERT(scheduler_current_delay_ms() > 0U);
    return true;
}

/** WAITING_CONFIRM with a persisted expected_version that does not match
 * OTA_FW_VERSION -> MCUBoot rejected the swap -> rollback() + ROLLBACK
 * reported, persist cleared. */
static bool test_aa_finalize_boot_version_mismatch_rollback(void *params)
{
    (void)params;
    reset_all();

    updater_ctx_t updater = build_test_updater();
    TEST_ASSERT_NOT_NULL(updater.ota_ctx);

    el2go_ota_pending_status_t pending = { 0 };
    (void)strncpy(pending.update_id, "update-vm", sizeof(pending.update_id) - 1U);
    (void)strncpy(pending.package_id, "package-vm", sizeof(pending.package_id) - 1U);
    pending.outcome = (uint8_t)EL2GO_OTA_OUTCOME_SUCCESS;
    pending.valid = EL2GO_OTA_STATUS_VALID_MAGIC;
    el2go_ota_lib_mock_set_pending_status(&pending);

    agent_persist_t persist = { 0 };
    persist.state = (uint32_t)AGENT_STATE_REBOOT;
    persist.valid = EL2GO_OTA_PERSIST_VALID_MAGIC;
    (void)strncpy(persist.update_id, "update-vm", sizeof(persist.update_id) - 1U);
    (void)strncpy(persist.expected_version, "99.99.99", sizeof(persist.expected_version) - 1U);
    (void)el2go_ota_persist_write(&persist);

    fwual_mock_set_lifecycle_state_for_test(FWUAL_STATE_WAITING_CONFIRM);
    updater_finalize_boot(&updater, FWUAL_STATE_WAITING_CONFIRM);

    TEST_ASSERT_EQUAL(FWUAL_STATE_ROLLED_BACK, fwual_get_state());
    TEST_ASSERT_EQUAL(EL2GO_OTA_OUTCOME_ROLLBACK, el2go_ota_lib_mock_last_scheduled_outcome());

    agent_persist_t after = { 0 };
    (void)el2go_ota_persist_read(&after);
    TEST_ASSERT((uint32_t)after.valid != EL2GO_OTA_PERSIST_VALID_MAGIC);
    return true;
}

/** FWUAL_STATE_FAILED with a valid persisted update -> FAILURE reported
 * with the persisted update/package id, then persist cleared. */
static bool test_aa_finalize_boot_fwual_failed_reports_failure(void *params)
{
    (void)params;
    reset_all();

    updater_ctx_t updater = build_test_updater();
    TEST_ASSERT_NOT_NULL(updater.ota_ctx);

    agent_persist_t persist = { 0 };
    persist.state = (uint32_t)AGENT_STATE_DOWNLOAD;
    persist.valid = EL2GO_OTA_PERSIST_VALID_MAGIC;
    (void)strncpy(persist.update_id, "update-failed", sizeof(persist.update_id) - 1U);
    (void)strncpy(persist.package_id, "package-failed", sizeof(persist.package_id) - 1U);
    (void)el2go_ota_persist_write(&persist);

    updater_finalize_boot(&updater, FWUAL_STATE_FAILED);

    TEST_ASSERT_EQUAL(EL2GO_OTA_OUTCOME_FAILURE, el2go_ota_lib_mock_last_reported_outcome());
    TEST_ASSERT_EQUAL(0, strcmp("update-failed", el2go_ota_lib_mock_last_reported_update_id()));

    agent_persist_t after = { 0 };
    (void)el2go_ota_persist_read(&after);
    TEST_ASSERT((uint32_t)after.valid != EL2GO_OTA_PERSIST_VALID_MAGIC);
    return true;
}

/** Default/IDLE fwual state with a stale valid persist record -> the
 * record is simply cleared (no report). */
static bool test_aa_finalize_boot_idle_clears_stale_persist(void *params)
{
    (void)params;
    reset_all();

    updater_ctx_t updater = build_test_updater();
    TEST_ASSERT_NOT_NULL(updater.ota_ctx);

    agent_persist_t persist = { 0 };
    persist.state = (uint32_t)AGENT_STATE_IDLE;
    persist.valid = EL2GO_OTA_PERSIST_VALID_MAGIC;
    (void)strncpy(persist.update_id, "stale-update", sizeof(persist.update_id) - 1U);
    (void)el2go_ota_persist_write(&persist);

    size_t reported_before = el2go_ota_lib_mock_report_call_count();

    updater_finalize_boot(&updater, FWUAL_STATE_IDLE);

    TEST_ASSERT_EQUAL((int)reported_before, (int)el2go_ota_lib_mock_report_call_count());

    agent_persist_t after = { 0 };
    (void)el2go_ota_persist_read(&after);
    TEST_ASSERT((uint32_t)after.valid != EL2GO_OTA_PERSIST_VALID_MAGIC);
    return true;
}

/** fwual_write() fails mid-chunk -> chunk_cb() propagates the error,
 * download/handoff fails, FAILURE reported. */
static bool test_aa_fwual_write_failure(void *params)
{
    (void)params;
    reset_all();

    updater_ctx_t updater = build_test_updater();
    TEST_ASSERT_NOT_NULL(updater.ota_ctx);

    uint8_t payload[64];
    memset(payload, 0x5A, sizeof(payload));
    el2go_ota_lib_mock_set_payload(payload, sizeof(payload));

    el2go_ota_update_info_t update;
    agent_fixture_make_update_info(&update, payload, sizeof(payload));
    agent_fixture_queue_update_available(&update);

    fwual_mock_set_write_fail_for_test(true);

    updater_run_check(&updater);

    fwual_mock_set_write_fail_for_test(false); /* persistent flag: clear before other tests run */

    TEST_ASSERT_EQUAL(EL2GO_OTA_OUTCOME_FAILURE, el2go_ota_lib_mock_last_reported_outcome());
    return true;
}

/** fwual_finalize_image() fails -> FAILURE reported. */
static bool test_aa_fwual_finalize_failure(void *params)
{
    (void)params;
    reset_all();

    updater_ctx_t updater = build_test_updater();
    TEST_ASSERT_NOT_NULL(updater.ota_ctx);

    uint8_t payload[16] = { 0 };
    el2go_ota_lib_mock_set_payload(payload, sizeof(payload));

    el2go_ota_update_info_t update;
    agent_fixture_make_update_info(&update, payload, sizeof(payload));
    agent_fixture_queue_update_available(&update);

    fwual_mock_set_finalize_fail_for_test(true);

    updater_run_check(&updater);

    TEST_ASSERT_EQUAL(EL2GO_OTA_OUTCOME_FAILURE, el2go_ota_lib_mock_last_reported_outcome());
    return true;
}

/** fwual_verify_image() fails -> FAILURE reported. */
static bool test_aa_fwual_verify_failure(void *params)
{
    (void)params;
    reset_all();

    updater_ctx_t updater = build_test_updater();
    TEST_ASSERT_NOT_NULL(updater.ota_ctx);

    uint8_t payload[16] = { 0 };
    el2go_ota_lib_mock_set_payload(payload, sizeof(payload));

    el2go_ota_update_info_t update;
    agent_fixture_make_update_info(&update, payload, sizeof(payload));
    agent_fixture_queue_update_available(&update);

    fwual_mock_set_verify_fail_for_test(true);

    updater_run_check(&updater);

    TEST_ASSERT_EQUAL(EL2GO_OTA_OUTCOME_FAILURE, el2go_ota_lib_mock_last_reported_outcome());
    return true;
}

/** Connection lost before a check -> updater_run_check() disconnects and
 * reconnects before proceeding. Reconnect succeeds, so the check still
 * runs normally. */
static bool test_aa_run_check_reconnect_success(void *params)
{
    (void)params;
    reset_all();

    updater_ctx_t updater = build_test_updater();
    TEST_ASSERT_NOT_NULL(updater.ota_ctx);

    el2go_ota_lib_mock_force_disconnected();
    agent_fixture_queue_no_update();

    updater_run_check(&updater);

    TEST_ASSERT_EQUAL(1U, (unsigned)el2go_ota_lib_mock_check_count());
    return true;
}

/** Connection lost before a check and the reconnect attempt itself fails
 * -> updater_run_check() backs off and returns without checking. */
static bool test_aa_run_check_reconnect_failure_backs_off(void *params)
{
    (void)params;
    reset_all();

    updater_ctx_t updater = build_test_updater();
    TEST_ASSERT_NOT_NULL(updater.ota_ctx);

    uint32_t base_ms = (uint32_t)CONFIG_EL2GO_OTA_ADV_POLL_INTERVAL_S * 1000U;

    el2go_ota_lib_mock_force_disconnected();
    el2go_ota_lib_mock_set_connect_fail(true);

    updater_run_check(&updater);

    TEST_ASSERT_EQUAL(0U, (unsigned)el2go_ota_lib_mock_check_count());
    TEST_ASSERT(scheduler_current_delay_ms() != base_ms);
    return true;
}

void register_ota_agent_advanced_internal_tests(void)
{
    TEST_REGISTER_ID("-", test_aa_policy_cancel_no_update);
    TEST_REGISTER_ID("-", test_aa_policy_blackout_wraparound);
    TEST_REGISTER_ID("-", test_aa_policy_blackout_unknown_hour);
    TEST_REGISTER_ID("-", test_aa_policy_defer_boundary);
    TEST_REGISTER_ID("-", test_aa_scheduler_backoff_caps);
    TEST_REGISTER_ID("-", test_aa_scheduler_reset_restores_interval);
    TEST_REGISTER_ID("-", test_aa_scheduler_rearm_overrides_delay);
    TEST_REGISTER_ID("-", test_aa_checksum_too_short);
    TEST_REGISTER_ID("-", test_aa_checksum_alg_unsupported);
    TEST_REGISTER_ID("-", test_aa_prepare_image_failure);
    TEST_REGISTER_ID("-", test_aa_chunk_exceeds_max_write_size);
    TEST_REGISTER_ID("-", test_aa_no_update_calls_scheduler_reset);
    TEST_REGISTER_ID("-", test_aa_scheduler_step_invokes_callback);
    TEST_REGISTER_ID("-", test_aa_checksum_malformed_hex);
    TEST_REGISTER_ID("-", test_aa_check_storage_no_space);
    TEST_REGISTER_ID("-", test_aa_check_for_updates_failure_backs_off);
    TEST_REGISTER_ID("-", test_aa_run_check_policy_defer);
    TEST_REGISTER_ID("-", test_aa_finalize_boot_version_mismatch_rollback);
    TEST_REGISTER_ID("-", test_aa_finalize_boot_fwual_failed_reports_failure);
    TEST_REGISTER_ID("-", test_aa_finalize_boot_idle_clears_stale_persist);
    TEST_REGISTER_ID("-", test_aa_fwual_write_failure);
    TEST_REGISTER_ID("-", test_aa_fwual_finalize_failure);
    TEST_REGISTER_ID("-", test_aa_fwual_verify_failure);
    TEST_REGISTER_ID("-", test_aa_run_check_reconnect_success);
    TEST_REGISTER_ID("-", test_aa_run_check_reconnect_failure_backs_off);
}
