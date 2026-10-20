/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

/*
 * Component tests for the advanced OTA agent, real NVS + flash-simulator.
 * See doc/testing/ota_agent_test_plan.md for the test list, IDs, and rationale.
 */

#include <string.h>
#include <psa/crypto.h>

#include "test_el2go_ota_agent_advanced_internal_zephyr.h"

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
static int64_t s_epoch_ms;

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
    };
    (void)el2go_ota_init(&updater.ota_ctx, &config);
    (void)el2go_ota_connect(updater.ota_ctx);
    return updater;
}

/* Two-package update; each package's checksum matches payload_N. Advanced-
 * suite-only helper (the core agent has no multi-package flow to exercise). */
static void make_multi_update_info(el2go_ota_update_info_t *update, const uint8_t *payload0,
                                   size_t len0, const uint8_t *payload1, size_t len1)
{
    memset(update, 0, sizeof(*update));
    (void)strncpy(update->update_id, "update-multi", sizeof(update->update_id) - 1U);
    update->package_count = 2U;

    el2go_ota_package_info_t *pkg0 = &update->packages[0];
    (void)strncpy(pkg0->package_id, "package-0", sizeof(pkg0->package_id) - 1U);
    pkg0->file_count = 1U;
    (void)strncpy(pkg0->files[0].file_id, "file-0", sizeof(pkg0->files[0].file_id) - 1U);
    pkg0->files[0].size = (int64_t)len0;
    pkg0->files[0].checksum_algorithm = EL2GO_OTA_CHECKSUM_ALG_SHA256;
    agent_fixture_sha256_hex(payload0, len0, pkg0->files[0].checksum);

    el2go_ota_package_info_t *pkg1 = &update->packages[1];
    (void)strncpy(pkg1->package_id, "package-1", sizeof(pkg1->package_id) - 1U);
    pkg1->file_count = 1U;
    (void)strncpy(pkg1->files[0].file_id, "file-1", sizeof(pkg1->files[0].file_id) - 1U);
    pkg1->files[0].size = (int64_t)len1;
    pkg1->files[0].checksum_algorithm = EL2GO_OTA_CHECKSUM_ALG_SHA256;
    agent_fixture_sha256_hex(payload1, len1, pkg1->files[0].checksum);
}

/* See the matching comment in the unit-level suite for why s_epoch_ms
 * strictly increases rather than using a fixed post-reset offset. */
static void reset_all(void)
{
    el2go_ota_lib_mock_reset();
    wrap_app_sys_reset();
    s_epoch_ms += 7LL * 24LL * 3600LL * 1000LL;
    wrap_app_sys_set_uptime_ms(s_epoch_ms);
    scheduler_configure(NULL, NULL);
    scheduler_reset();
    (void)fwual_init();
    (void)el2go_ota_persist_clear();
}

/** OTA_CT_AA_1.1: single image happy path, real NVS. */
static test_result_t test_aa_ct_single_image_happy_path(void)
{
    TEST_REQUIRE_CAP(CT_CAP_REAL_FLASH);
    reset_all();

    updater_ctx_t updater = build_test_updater();
    TEST_ASSERT_NOT_NULL(updater.ota_ctx);

    uint8_t payload[256];
    memset(payload, 0x5A, sizeof(payload));
    el2go_ota_lib_mock_set_payload(payload, sizeof(payload));

    el2go_ota_update_info_t update;
    agent_fixture_make_update_info(&update, payload, sizeof(payload));
    agent_fixture_queue_update_available(&update);

    updater_run_check(&updater);

    TEST_ASSERT_EQ(FWUAL_STATE_REBOOT_REQUIRED, fwual_get_state());
    TEST_ASSERT_EQ(1U, wrap_app_sys_activate_call_count());

    fwual_mock_set_lifecycle_state_for_test(FWUAL_STATE_WAITING_CONFIRM);
    updater_finalize_boot(&updater, FWUAL_STATE_WAITING_CONFIRM);

    TEST_ASSERT_EQ(FWUAL_STATE_ACTIVE, fwual_get_state());
    TEST_ASSERT_EQ(1U, el2go_ota_lib_mock_pending_delivered_count());
    return TEST_PASS;
}

/** OTA_CT_AA_1.2: no update available, 2 cycles, agent stays idle. */
static test_result_t test_aa_ct_no_update_stays_idle(void)
{
    TEST_REQUIRE_CAP(CT_CAP_REAL_FLASH);
    reset_all();

    updater_ctx_t updater = build_test_updater();
    TEST_ASSERT_NOT_NULL(updater.ota_ctx);

    agent_fixture_queue_no_update();
    agent_fixture_queue_no_update();

    updater_run_check(&updater);
    updater_run_check(&updater);

    TEST_ASSERT_EQ(2U, el2go_ota_lib_mock_check_count());
    TEST_ASSERT_EQ(0U, el2go_ota_lib_mock_download_call_count());
    return TEST_PASS;
}

/** OTA_CT_AA_1.3: download failure -> FAILURE reported. */
static test_result_t test_aa_ct_download_failure_reports_failure(void)
{
    TEST_REQUIRE_CAP(CT_CAP_REAL_FLASH);
    reset_all();

    updater_ctx_t updater = build_test_updater();
    TEST_ASSERT_NOT_NULL(updater.ota_ctx);

    uint8_t payload[16] = { 0 };
    el2go_ota_lib_mock_set_payload(payload, sizeof(payload));
    el2go_ota_update_info_t update;
    agent_fixture_make_update_info(&update, payload, sizeof(payload));
    agent_fixture_queue_update_available(&update);

    el2go_ota_lib_mock_set_download_hard_fail(true);

    updater_run_check(&updater);

    TEST_ASSERT_EQ(EL2GO_OTA_OUTCOME_FAILURE, el2go_ota_lib_mock_last_reported_outcome());
    return TEST_PASS;
}

/** OTA_CT_AA_1.4: post-reboot ROLLED_BACK -> ROLLBACK reported, NVS cleared. */
static test_result_t test_aa_ct_rollback_scenario(void)
{
    TEST_REQUIRE_CAP(CT_CAP_REAL_FLASH);
    reset_all();

    updater_ctx_t updater = build_test_updater();
    TEST_ASSERT_NOT_NULL(updater.ota_ctx);

    el2go_ota_pending_status_t pending = { 0 };
    (void)strncpy(pending.update_id, "update-x", sizeof(pending.update_id) - 1U);
    (void)strncpy(pending.package_id, "package-x", sizeof(pending.package_id) - 1U);
    pending.outcome = (uint8_t)EL2GO_OTA_OUTCOME_SUCCESS;
    pending.valid = EL2GO_OTA_STATUS_VALID_MAGIC;
    el2go_ota_lib_mock_set_pending_status(&pending);

    agent_persist_t persist = { 0 };
    persist.state = (uint32_t)AGENT_STATE_REBOOT;
    persist.valid = EL2GO_OTA_PERSIST_VALID_MAGIC;
    (void)strncpy(persist.update_id, "update-x", sizeof(persist.update_id) - 1U);
    (void)el2go_ota_persist_write(&persist);

    fwual_mock_set_lifecycle_state_for_test(FWUAL_STATE_ROLLED_BACK);
    updater_finalize_boot(&updater, FWUAL_STATE_ROLLED_BACK);

    TEST_ASSERT_EQ(EL2GO_OTA_OUTCOME_ROLLBACK, el2go_ota_lib_mock_last_scheduled_outcome());

    agent_persist_t after = { 0 };
    (void)el2go_ota_persist_read(&after);
    TEST_ASSERT_NE(EL2GO_OTA_PERSIST_VALID_MAGIC, after.valid);
    return TEST_PASS;
}

/** OTA_CT_AA_1.6: policy blackout blocks update; agent stays idle. */
static test_result_t test_aa_ct_policy_blackout(void)
{
    TEST_REQUIRE_CAP(CT_CAP_REAL_FLASH);
    reset_all();

    updater_ctx_t updater = build_test_updater();
    TEST_ASSERT_NOT_NULL(updater.ota_ctx);

    wrap_app_sys_set_hour_of_day(23); /* inside configured 22-6 blackout window */

    uint8_t payload[16] = { 0 };
    el2go_ota_lib_mock_set_payload(payload, sizeof(payload));
    el2go_ota_update_info_t update;
    agent_fixture_make_update_info(&update, payload, sizeof(payload));
    agent_fixture_queue_update_available(&update);

    updater_run_check(&updater);

    TEST_ASSERT_EQ(0U, el2go_ota_lib_mock_download_call_count());
    TEST_ASSERT_EQ(3600U * 1000U, scheduler_current_delay_ms());
    return TEST_PASS;
}

/** OTA_CT_AA_1.8: server recovers after N failures -> retries then succeeds. */
static test_result_t test_aa_ct_retry_then_succeed(void)
{
    TEST_REQUIRE_CAP(CT_CAP_REAL_FLASH);
    reset_all();

    updater_ctx_t updater = build_test_updater();
    TEST_ASSERT_NOT_NULL(updater.ota_ctx);

    uint8_t payload[64];
    memset(payload, 0x11, sizeof(payload));
    el2go_ota_lib_mock_set_payload(payload, sizeof(payload));
    el2go_ota_update_info_t update;
    agent_fixture_make_update_info(&update, payload, sizeof(payload));
    agent_fixture_queue_update_available(&update);

    el2go_ota_lib_mock_set_download_fail_count(3U);

    updater_run_check(&updater);

    TEST_ASSERT_EQ(4U, el2go_ota_lib_mock_download_call_count());
    TEST_ASSERT_EQ(FWUAL_STATE_REBOOT_REQUIRED, fwual_get_state());
    return TEST_PASS;
}

/** OTA_CT_AA_1.9: max retry exceeded -> FAILURE after exactly MAX_RETRIES attempts. */
static test_result_t test_aa_ct_max_retry_exceeded(void)
{
    TEST_REQUIRE_CAP(CT_CAP_REAL_FLASH);
    reset_all();

    updater_ctx_t updater = build_test_updater();
    TEST_ASSERT_NOT_NULL(updater.ota_ctx);

    uint8_t payload[16] = { 0 };
    el2go_ota_lib_mock_set_payload(payload, sizeof(payload));
    el2go_ota_update_info_t update;
    agent_fixture_make_update_info(&update, payload, sizeof(payload));
    agent_fixture_queue_update_available(&update);

    el2go_ota_lib_mock_set_download_hard_fail(true);

    updater_run_check(&updater);

    TEST_ASSERT_EQ((long)CONFIG_EL2GO_OTA_ADV_DOWNLOAD_MAX_RETRIES,
                   (long)el2go_ota_lib_mock_download_call_count());
    TEST_ASSERT_EQ(EL2GO_OTA_OUTCOME_FAILURE, el2go_ota_lib_mock_last_reported_outcome());
    return TEST_PASS;
}

/** OTA_CT_AA_1.10: periodic check at configured interval, real fake-clock
 * cadence. __wrap_el2go_app_sys_wait() advances the fake clock by the ms
 * waited, so no manual advance is needed here. */
static test_result_t test_aa_ct_scheduling_cadence(void)
{
    TEST_REQUIRE_CAP(CT_CAP_REAL_FLASH);
    reset_all();

    uint32_t interval_ms = (uint32_t)CONFIG_EL2GO_OTA_ADV_POLL_INTERVAL_S * 1000U;

    scheduler_step(); /* first step: target was armed at "now", wait == 0 */
    TEST_ASSERT_EQ(0, (long)wrap_app_sys_last_wait_ms());

    for (int i = 0; i < 5; i++) {
        scheduler_step();
        /* Each subsequent step waits exactly one poll interval. */
        TEST_ASSERT_EQ((long)interval_ms, (long)wrap_app_sys_last_wait_ms());
    }

    return TEST_PASS;
}

/** OTA_CT_AA_1.11: NVS round-trip via direct persist read/write. */
static test_result_t test_aa_ct_nvs_round_trip(void)
{
    TEST_REQUIRE_CAP(CT_CAP_REAL_FLASH);
    reset_all();

    agent_persist_t in = { 0 };
    in.state = (uint32_t)AGENT_STATE_DOWNLOAD;
    in.valid = EL2GO_OTA_PERSIST_VALID_MAGIC;
    (void)strncpy(in.update_id, "nvs-test-update", sizeof(in.update_id) - 1U);
    (void)strncpy(in.package_id, "nvs-test-package", sizeof(in.package_id) - 1U);

    TEST_ASSERT_EQ(EL2GO_OTA_PERSIST_OK, (long)el2go_ota_persist_write(&in));

    agent_persist_t out = { 0 };
    TEST_ASSERT_EQ(EL2GO_OTA_PERSIST_OK, (long)el2go_ota_persist_read(&out));

    TEST_ASSERT_EQ(EL2GO_OTA_PERSIST_VALID_MAGIC, out.valid);
    TEST_ASSERT_STR_EQ(in.update_id, out.update_id);
    TEST_ASSERT_STR_EQ(in.package_id, out.package_id);
    return TEST_PASS;
}

/** OTA_CT_AA_1.12: interrupted session (FWUAL_STATE_WRITING) survives
 * finalize_boot() without clearing the record. */
static test_result_t test_aa_ct_interrupted_session_survives(void)
{
    TEST_REQUIRE_CAP(CT_CAP_REAL_FLASH);
    reset_all();

    updater_ctx_t updater = build_test_updater();
    TEST_ASSERT_NOT_NULL(updater.ota_ctx);

    agent_persist_t seed = { 0 };
    seed.state = (uint32_t)AGENT_STATE_DOWNLOAD;
    seed.valid = EL2GO_OTA_PERSIST_VALID_MAGIC;
    (void)strncpy(seed.update_id, "interrupted-update", sizeof(seed.update_id) - 1U);
    (void)el2go_ota_persist_write(&seed);

    updater_finalize_boot(&updater, FWUAL_STATE_WRITING);

    agent_persist_t after = { 0 };
    (void)el2go_ota_persist_read(&after);
    TEST_ASSERT_EQ(EL2GO_OTA_PERSIST_VALID_MAGIC, after.valid);
    TEST_ASSERT_STR_EQ(seed.update_id, after.update_id);
    return TEST_PASS;
}

/** OTA_CT_AA_1.13: telemetry report retried until acknowledged. */
static test_result_t test_aa_ct_telemetry_retried_until_ack(void)
{
    TEST_REQUIRE_CAP(CT_CAP_REAL_FLASH);
    reset_all();

    updater_ctx_t updater = build_test_updater();
    TEST_ASSERT_NOT_NULL(updater.ota_ctx);

    uint8_t payload[16] = { 0 };
    el2go_ota_lib_mock_set_payload(payload, sizeof(payload));
    el2go_ota_update_info_t update;
    agent_fixture_make_update_info(&update, payload, sizeof(payload));
    agent_fixture_queue_update_available(&update);

    el2go_ota_lib_mock_set_download_hard_fail(true);
    el2go_ota_lib_mock_set_report_reject_count(2U);

    updater_run_check(&updater);

    TEST_ASSERT_EQ(3U, el2go_ota_lib_mock_report_call_count());
    TEST_ASSERT_EQ(EL2GO_OTA_OUTCOME_FAILURE, el2go_ota_lib_mock_last_reported_outcome());
    return TEST_PASS;
}

/** OTA_CT_AA_1.14: two-image update committed atomically, activate once. */
static test_result_t test_aa_ct_multi_image_happy_path(void)
{
    TEST_REQUIRE_CAP(CT_CAP_REAL_FLASH);
    reset_all();

    updater_ctx_t updater = build_test_updater();
    TEST_ASSERT_NOT_NULL(updater.ota_ctx);

    uint8_t payload0[64];
    uint8_t payload1[96];
    memset(payload0, 0x01, sizeof(payload0));
    memset(payload1, 0x02, sizeof(payload1));

    /* The mock cannot script a different payload per package/call, so
     * both packages use payload0's content to exercise the two-package/
     * commit-once control flow. */
    el2go_ota_lib_mock_set_payload(payload0, sizeof(payload0));

    el2go_ota_update_info_t update;
    make_multi_update_info(&update, payload0, sizeof(payload0), payload0, sizeof(payload0));
    agent_fixture_queue_update_available(&update);

    updater_run_check(&updater);

    TEST_ASSERT_EQ(FWUAL_STATE_REBOOT_REQUIRED, fwual_get_state());
    TEST_ASSERT_EQ(1U, wrap_app_sys_activate_call_count());
    return TEST_PASS;
}

/** OTA_CT_AA_2.1: Idle -> Check -> Download, NVS updated. */
static test_result_t test_aa_ct_state_idle_check_download(void)
{
    TEST_REQUIRE_CAP(CT_CAP_REAL_FLASH);
    reset_all();

    updater_ctx_t updater = build_test_updater();
    TEST_ASSERT_NOT_NULL(updater.ota_ctx);

    uint8_t payload[16] = { 0 };
    el2go_ota_lib_mock_set_payload(payload, sizeof(payload));
    el2go_ota_update_info_t update;
    agent_fixture_make_update_info(&update, payload, sizeof(payload));
    agent_fixture_queue_update_available(&update);

    updater_run_check(&updater);

    TEST_ASSERT_EQ(1U, el2go_ota_lib_mock_check_count());
    TEST_ASSERT_EQ(1U, el2go_ota_lib_mock_download_call_count());
    return TEST_PASS;
}

/** OTA_CT_AA_2.3: Reboot -> Finalize -> SUCCESS. Seeds a pending status
 * (as the real flow would have left before rebooting) so finalize_boot()
 * has something to deliver. */
static test_result_t test_aa_ct_state_reboot_finalize_success(void)
{
    TEST_REQUIRE_CAP(CT_CAP_REAL_FLASH);
    reset_all();

    updater_ctx_t updater = build_test_updater();
    TEST_ASSERT_NOT_NULL(updater.ota_ctx);

    el2go_ota_pending_status_t pending = { 0 };
    (void)strncpy(pending.update_id, "update-1", sizeof(pending.update_id) - 1U);
    (void)strncpy(pending.package_id, "package-1", sizeof(pending.package_id) - 1U);
    pending.outcome = (uint8_t)EL2GO_OTA_OUTCOME_SUCCESS;
    pending.valid = EL2GO_OTA_STATUS_VALID_MAGIC;
    el2go_ota_lib_mock_set_pending_status(&pending);

    fwual_mock_set_lifecycle_state_for_test(FWUAL_STATE_WAITING_CONFIRM);
    updater_finalize_boot(&updater, FWUAL_STATE_WAITING_CONFIRM);

    TEST_ASSERT_EQ(FWUAL_STATE_ACTIVE, fwual_get_state());
    TEST_ASSERT_EQ(1U, el2go_ota_lib_mock_pending_delivered_count());
    return TEST_PASS;
}

/** OTA_CT_AA_2.5: persistent download failure -> retries then FAILURE. */
static test_result_t test_aa_ct_state_download_failure_retry_failure(void)
{
    TEST_REQUIRE_CAP(CT_CAP_REAL_FLASH);
    reset_all();

    updater_ctx_t updater = build_test_updater();
    TEST_ASSERT_NOT_NULL(updater.ota_ctx);

    uint8_t payload[16] = { 0 };
    el2go_ota_lib_mock_set_payload(payload, sizeof(payload));
    el2go_ota_update_info_t update;
    agent_fixture_make_update_info(&update, payload, sizeof(payload));
    agent_fixture_queue_update_available(&update);

    el2go_ota_lib_mock_set_download_hard_fail(true);

    updater_run_check(&updater);

    TEST_ASSERT_EQ((long)CONFIG_EL2GO_OTA_ADV_DOWNLOAD_MAX_RETRIES,
                   (long)el2go_ota_lib_mock_download_call_count());
    TEST_ASSERT_EQ(EL2GO_OTA_OUTCOME_FAILURE, el2go_ota_lib_mock_last_reported_outcome());
    return TEST_PASS;
}

/** OTA_CT_AA_2.6: scheduler drift correction -- overshoot the clock between
 * two steps, the following wait is shortened by the overshoot. */
static test_result_t test_aa_ct_scheduler_drift_correction(void)
{
    TEST_REQUIRE_CAP(CT_CAP_REAL_FLASH);
    reset_all();

    uint32_t interval_ms = (uint32_t)CONFIG_EL2GO_OTA_ADV_POLL_INTERVAL_S * 1000U;

    scheduler_step(); /* arms next target at interval_ms from now */

    uint32_t overshoot_ms = interval_ms / 2U;
    wrap_app_sys_advance_ms((int64_t)interval_ms + (int64_t)overshoot_ms);

    scheduler_step();

    /* wait_ms was clamped to 0 (target already passed) by scheduler_step(). */
    TEST_ASSERT_EQ(0, (long)wrap_app_sys_last_wait_ms());
    return TEST_PASS;
}

/* ---- suite table ---------------------------------------------------------- */

TEST_SUITE_BEGIN(ota_agent_advanced_internal)
TEST_REGISTER("OTA_CT_AA_1.1", test_aa_ct_single_image_happy_path)
TEST_REGISTER("OTA_CT_AA_1.2", test_aa_ct_no_update_stays_idle)
TEST_REGISTER("OTA_CT_AA_1.3", test_aa_ct_download_failure_reports_failure)
TEST_REGISTER("OTA_CT_AA_1.4", test_aa_ct_rollback_scenario)
TEST_REGISTER("OTA_CT_AA_1.6", test_aa_ct_policy_blackout)
TEST_REGISTER("OTA_CT_AA_1.8", test_aa_ct_retry_then_succeed)
TEST_REGISTER("OTA_CT_AA_1.9", test_aa_ct_max_retry_exceeded)
TEST_REGISTER("OTA_CT_AA_1.10", test_aa_ct_scheduling_cadence)
TEST_REGISTER("OTA_CT_AA_1.11", test_aa_ct_nvs_round_trip)
TEST_REGISTER("OTA_CT_AA_1.12", test_aa_ct_interrupted_session_survives)
TEST_REGISTER("OTA_CT_AA_1.13", test_aa_ct_telemetry_retried_until_ack)
TEST_REGISTER("OTA_CT_AA_1.14", test_aa_ct_multi_image_happy_path)
TEST_REGISTER("OTA_CT_AA_2.1", test_aa_ct_state_idle_check_download)
TEST_REGISTER("OTA_CT_AA_2.3", test_aa_ct_state_reboot_finalize_success)
TEST_REGISTER("OTA_CT_AA_2.5", test_aa_ct_state_download_failure_retry_failure)
TEST_REGISTER("OTA_CT_AA_2.6", test_aa_ct_scheduler_drift_correction)
TEST_SUITE_END(ota_agent_advanced_internal)
