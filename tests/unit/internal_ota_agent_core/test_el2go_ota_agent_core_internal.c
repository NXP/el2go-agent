/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

/*
 * Internal ota_agent_core unit tests.
 *
 * main.c has no public header (reference sample, not a library), so this
 * file white-box tests it by including main.c directly with main() renamed
 * away. Same pattern as tests/unit/internal_ota_lib/test_el2go_ota_grpc_internal.c.
 */

#include "test_suites.h"

#include <string.h>
#include <psa/crypto.h>

#include "test_framework.h"

#include "agent_test_fixtures.h"
#include "el2go_ota_lib_mock.h"
#include "fwual_mock.h"
#include "wrap_app_sys.h"
#include "fwual/fwual.h"
#include "ota/el2go_ota_lib.h"

#define main el2go_ota_agent_core_main_unused
#include "el2go_ota_agent_core/src/main.c"
#undef main

/* Test helpers */

/* Dummy non-NULL CA chain: __wrap_el2go_ota_init() rejects a NULL/zero
 * server_ca_chain the same way the real el2go_ota_init() contract does. */
static const uint8_t k_dummy_ca_chain[] = { 0x30, 0x00 };

static core_updater_ctx_t build_test_updater(void)
{
    core_updater_ctx_t updater = { 0 };

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

static void reset_all_mocks(void)
{
    el2go_ota_lib_mock_reset();
    wrap_app_sys_reset();
    (void)fwual_init();
}

/** Checksum string shorter than 64 hex chars -> download/handoff fails,
 * outcome FAILURE is reported to the server. */
static bool test_ac_checksum_too_short(void *params)
{
    (void)params;
    reset_all_mocks();

    core_updater_ctx_t updater = build_test_updater();
    TEST_ASSERT_NOT_NULL(updater.ota_ctx);

    const uint8_t payload[16] = { 0 };
    el2go_ota_lib_mock_set_payload(payload, sizeof(payload));

    el2go_ota_update_info_t update;
    agent_fixture_make_update_info(&update, payload, sizeof(payload));
    update.packages[0].files[0].checksum[10] = '\0'; /* truncate to < 64 chars */

    agent_fixture_queue_update_available(&update);

    core_updater_run_check(&updater);

    TEST_ASSERT_EQUAL(EL2GO_OTA_OUTCOME_FAILURE, el2go_ota_lib_mock_last_reported_outcome());
    return true;
}

/** Non-hex characters in the checksum string -> FAILURE reported. */
static bool test_ac_checksum_invalid_hex(void *params)
{
    (void)params;
    reset_all_mocks();

    core_updater_ctx_t updater = build_test_updater();
    TEST_ASSERT_NOT_NULL(updater.ota_ctx);

    const uint8_t payload[16] = { 0 };
    el2go_ota_lib_mock_set_payload(payload, sizeof(payload));

    el2go_ota_update_info_t update;
    agent_fixture_make_update_info(&update, payload, sizeof(payload));
    update.packages[0].files[0].checksum[0] = 'z'; /* not a hex digit */
    update.packages[0].files[0].checksum[1] = 'z';

    agent_fixture_queue_update_available(&update);

    core_updater_run_check(&updater);

    TEST_ASSERT_EQUAL(EL2GO_OTA_OUTCOME_FAILURE, el2go_ota_lib_mock_last_reported_outcome());
    return true;
}

/** Unsupported checksum algorithm id -> FAILURE reported, no download attempted. */
static bool test_ac_checksum_alg_unsupported(void *params)
{
    (void)params;
    reset_all_mocks();

    core_updater_ctx_t updater = build_test_updater();
    TEST_ASSERT_NOT_NULL(updater.ota_ctx);

    const uint8_t payload[16] = { 0 };
    el2go_ota_lib_mock_set_payload(payload, sizeof(payload));

    el2go_ota_update_info_t update;
    agent_fixture_make_update_info(&update, payload, sizeof(payload));
    update.packages[0].files[0].checksum_algorithm = 0x1234; /* neither SHA256 nor UNSPECIFIED */

    agent_fixture_queue_update_available(&update);

    core_updater_run_check(&updater);

    TEST_ASSERT_EQUAL(EL2GO_OTA_OUTCOME_FAILURE, el2go_ota_lib_mock_last_reported_outcome());
    TEST_ASSERT_EQUAL(0U, (unsigned)el2go_ota_lib_mock_download_call_count());
    return true;
}

/** Downloaded chunk larger than fwual_caps.max_write_size -> chunk_cb()
 * rejects it, FAILURE is reported. */
static bool test_ac_chunk_exceeds_max_write_size(void *params)
{
    (void)params;
    reset_all_mocks();

    core_updater_ctx_t updater = build_test_updater();
    TEST_ASSERT_NOT_NULL(updater.ota_ctx);

    updater.fwual_caps.max_write_size = 8U; /* smaller than the mock's chunk size */

    uint8_t payload[64];
    memset(payload, 0xAB, sizeof(payload));
    el2go_ota_lib_mock_set_payload(payload, sizeof(payload));

    el2go_ota_update_info_t update;
    agent_fixture_make_update_info(&update, payload, sizeof(payload));
    agent_fixture_queue_update_available(&update);

    core_updater_run_check(&updater);

    TEST_ASSERT_EQUAL(EL2GO_OTA_OUTCOME_FAILURE, el2go_ota_lib_mock_last_reported_outcome());
    return true;
}

/** fwual_check_storage() reports FWUAL_ERR_NO_SPACE -> FAILURE reported. */
static bool test_ac_storage_check_no_space(void *params)
{
    (void)params;
    reset_all_mocks();

    core_updater_ctx_t updater = build_test_updater();
    TEST_ASSERT_NOT_NULL(updater.ota_ctx);

    uint8_t payload[16] = { 0 };
    el2go_ota_lib_mock_set_payload(payload, sizeof(payload));

    el2go_ota_update_info_t update;
    agent_fixture_make_update_info(&update, payload, sizeof(payload));
    agent_fixture_queue_update_available(&update);

    fwual_mock_set_check_storage_fail_for_test(true);

    core_updater_run_check(&updater);

    TEST_ASSERT_EQUAL(EL2GO_OTA_OUTCOME_FAILURE, el2go_ota_lib_mock_last_reported_outcome());
    return true;
}

/** fwual_prepare_image() fails -> FAILURE reported. */
static bool test_ac_prepare_image_failure(void *params)
{
    (void)params;
    reset_all_mocks();

    core_updater_ctx_t updater = build_test_updater();
    TEST_ASSERT_NOT_NULL(updater.ota_ctx);

    uint8_t payload[16] = { 0 };
    el2go_ota_lib_mock_set_payload(payload, sizeof(payload));

    el2go_ota_update_info_t update;
    agent_fixture_make_update_info(&update, payload, sizeof(payload));
    agent_fixture_queue_update_available(&update);

    fwual_mock_set_prepare_fail_for_test(true);

    core_updater_run_check(&updater);

    TEST_ASSERT_EQUAL(EL2GO_OTA_OUTCOME_FAILURE, el2go_ota_lib_mock_last_reported_outcome());
    return true;
}

/** el2go_ota_download_package() hard-fails -> FAILURE reported. */
static bool test_ac_download_hard_failure(void *params)
{
    (void)params;
    reset_all_mocks();

    core_updater_ctx_t updater = build_test_updater();
    TEST_ASSERT_NOT_NULL(updater.ota_ctx);

    uint8_t payload[16] = { 0 };
    el2go_ota_lib_mock_set_payload(payload, sizeof(payload));

    el2go_ota_update_info_t update;
    agent_fixture_make_update_info(&update, payload, sizeof(payload));
    agent_fixture_queue_update_available(&update);

    el2go_ota_lib_mock_set_download_hard_fail(true);

    core_updater_run_check(&updater);

    TEST_ASSERT_EQUAL(EL2GO_OTA_OUTCOME_FAILURE, el2go_ota_lib_mock_last_reported_outcome());
    return true;
}

/** Connection lost and reconnect fails -> connect_fail_count increments,
 * el2go_ota_check_for_updates() is never reached. */
static bool test_ac_reconnect_failure_counted(void *params)
{
    (void)params;
    reset_all_mocks();

    core_updater_ctx_t updater = build_test_updater();
    TEST_ASSERT_NOT_NULL(updater.ota_ctx);

    (void)el2go_ota_disconnect(updater.ota_ctx);
    el2go_ota_lib_mock_set_connect_fail(true);

    size_t check_count_before = el2go_ota_lib_mock_check_count();

    core_updater_run_check(&updater);

    TEST_ASSERT_EQUAL(1U, (unsigned)updater.connect_fail_count);
    TEST_ASSERT_EQUAL((int)check_count_before, (int)el2go_ota_lib_mock_check_count());
    return true;
}

/** Connection lost, reconnect succeeds -> connect_fail_count resets to 0
 * and the check-for-updates call proceeds normally. */
static bool test_ac_reconnect_recovers(void *params)
{
    (void)params;
    reset_all_mocks();

    core_updater_ctx_t updater = build_test_updater();
    TEST_ASSERT_NOT_NULL(updater.ota_ctx);

    (void)el2go_ota_disconnect(updater.ota_ctx);
    agent_fixture_queue_no_update();

    core_updater_run_check(&updater);

    TEST_ASSERT_EQUAL(0U, (unsigned)updater.connect_fail_count);
    TEST_ASSERT_EQUAL(1U, (unsigned)el2go_ota_lib_mock_check_count());
    return true;
}

/** el2go_ota_check_for_updates() itself returns an error status -> function
 * returns early, no download/report activity. */
static bool test_ac_check_for_updates_error(void *params)
{
    (void)params;
    reset_all_mocks();

    core_updater_ctx_t updater = build_test_updater();
    TEST_ASSERT_NOT_NULL(updater.ota_ctx);

    el2go_ota_check_update_resp_t resp = { 0 };
    el2go_ota_lib_mock_queue_check_response(&resp, EL2GO_OTA_ERROR_NETWORK);

    core_updater_run_check(&updater);

    TEST_ASSERT_EQUAL(0U, (unsigned)el2go_ota_lib_mock_download_call_count());
    TEST_ASSERT_EQUAL(0U, (unsigned)el2go_ota_lib_mock_report_call_count());
    return true;
}

/** No update available across two consecutive checks -> check count == 2,
 * never reports a status. */
static bool test_ac_no_update_two_cycles(void *params)
{
    (void)params;
    reset_all_mocks();

    core_updater_ctx_t updater = build_test_updater();
    TEST_ASSERT_NOT_NULL(updater.ota_ctx);

    agent_fixture_queue_no_update();
    agent_fixture_queue_no_update();

    core_updater_run_check(&updater);
    core_updater_run_check(&updater);

    TEST_ASSERT_EQUAL(2U, (unsigned)el2go_ota_lib_mock_check_count());
    TEST_ASSERT_EQUAL(0U, (unsigned)el2go_ota_lib_mock_report_call_count());
    return true;
}

/** A package with file_count == 0 is skipped by the per-package loop, but
 * commit/activate still run for the (empty) session. */
static bool test_ac_empty_package_skipped(void *params)
{
    (void)params;
    reset_all_mocks();

    core_updater_ctx_t updater = build_test_updater();
    TEST_ASSERT_NOT_NULL(updater.ota_ctx);

    el2go_ota_check_update_resp_t resp = { 0 };
    resp.update_available = true;
    resp.update_count = 1U;
    (void)strncpy(resp.updates[0].update_id, "update-empty",
                  sizeof(resp.updates[0].update_id) - 1U);
    resp.updates[0].package_count = 1U;
    (void)strncpy(resp.updates[0].packages[0].package_id, "package-empty",
                  sizeof(resp.updates[0].packages[0].package_id) - 1U);
    resp.updates[0].packages[0].file_count = 0U; /* empty package -> skipped */
    resp.first_update_id = resp.updates[0].update_id;
    resp.first_package_id = resp.updates[0].packages[0].package_id;

    el2go_ota_lib_mock_queue_check_response(&resp, EL2GO_OTA_SUCCESS);

    core_updater_run_check(&updater);

    TEST_ASSERT_EQUAL(0U, (unsigned)el2go_ota_lib_mock_download_call_count());
    TEST_ASSERT_EQUAL(FWUAL_STATE_REBOOT_REQUIRED, fwual_get_state());
    return true;
}

/** Full single-image happy path: download, FWUAL handoff, commit, activate,
 * then boot finalization confirms the image and reports SUCCESS. */
static bool test_ac_happy_path_single_image(void *params)
{
    (void)params;
    reset_all_mocks();

    core_updater_ctx_t updater = build_test_updater();
    TEST_ASSERT_NOT_NULL(updater.ota_ctx);

    uint8_t payload[256];
    memset(payload, 0x5A, sizeof(payload));
    el2go_ota_lib_mock_set_payload(payload, sizeof(payload));

    el2go_ota_update_info_t update;
    agent_fixture_make_update_info(&update, payload, sizeof(payload));
    agent_fixture_queue_update_available(&update);

    /* Success path nulls updater.ota_ctx. */
    core_updater_run_check(&updater);

    TEST_ASSERT_EQUAL(FWUAL_STATE_REBOOT_REQUIRED, fwual_get_state());
    TEST_ASSERT_EQUAL(1U, (unsigned)wrap_app_sys_activate_call_count());
    TEST_ASSERT_NULL(updater.ota_ctx);

    /* Simulate reboot into the trial-boot state and finalize. */
    fwual_mock_set_lifecycle_state_for_test(FWUAL_STATE_WAITING_CONFIRM);
    core_updater_finalize_boot(&updater, FWUAL_STATE_WAITING_CONFIRM);

    TEST_ASSERT_EQUAL(FWUAL_STATE_ACTIVE, fwual_get_state());
    /* Success path schedules the report rather than calling report_status()
     * directly (that's only used on the FAILURE path). */
    TEST_ASSERT_EQUAL(EL2GO_OTA_OUTCOME_SUCCESS, el2go_ota_lib_mock_last_scheduled_outcome());
    TEST_ASSERT_EQUAL(0U, (unsigned)el2go_ota_lib_mock_report_call_count());
    return true;
}

/** core_updater_finalize_boot() is a no-op for FWUAL_STATE_IDLE: no report,
 * no state change. */
static bool test_ac_finalize_boot_noop_idle(void *params)
{
    (void)params;
    reset_all_mocks();

    core_updater_ctx_t updater = build_test_updater();
    TEST_ASSERT_NOT_NULL(updater.ota_ctx);

    fwual_mock_set_lifecycle_state_for_test(FWUAL_STATE_IDLE);
    core_updater_finalize_boot(&updater, FWUAL_STATE_IDLE);

    TEST_ASSERT_EQUAL(FWUAL_STATE_IDLE, fwual_get_state());
    TEST_ASSERT_EQUAL(0U, (unsigned)el2go_ota_lib_mock_report_call_count());
    return true;
}

/** core_updater_finalize_boot() is a no-op for FWUAL_STATE_ACTIVE: no
 * report, no state change. */
static bool test_ac_finalize_boot_noop_active(void *params)
{
    (void)params;
    reset_all_mocks();

    core_updater_ctx_t updater = build_test_updater();
    TEST_ASSERT_NOT_NULL(updater.ota_ctx);

    fwual_mock_set_lifecycle_state_for_test(FWUAL_STATE_ACTIVE);
    core_updater_finalize_boot(&updater, FWUAL_STATE_ACTIVE);

    TEST_ASSERT_EQUAL(FWUAL_STATE_ACTIVE, fwual_get_state());
    TEST_ASSERT_EQUAL(0U, (unsigned)el2go_ota_lib_mock_report_call_count());
    return true;
}

/**
 * @brief Register all internal OTA agent core tests with the test framework.
 */
void register_ota_agent_core_internal_tests(void)
{
    TEST_REGISTER_ID("-", test_ac_checksum_too_short);
    TEST_REGISTER_ID("-", test_ac_checksum_invalid_hex);
    TEST_REGISTER_ID("-", test_ac_checksum_alg_unsupported);
    TEST_REGISTER_ID("-", test_ac_chunk_exceeds_max_write_size);
    TEST_REGISTER_ID("-", test_ac_storage_check_no_space);
    TEST_REGISTER_ID("-", test_ac_prepare_image_failure);
    TEST_REGISTER_ID("-", test_ac_download_hard_failure);
    TEST_REGISTER_ID("-", test_ac_reconnect_failure_counted);
    TEST_REGISTER_ID("-", test_ac_reconnect_recovers);
    TEST_REGISTER_ID("-", test_ac_check_for_updates_error);
    TEST_REGISTER_ID("-", test_ac_no_update_two_cycles);
    TEST_REGISTER_ID("-", test_ac_empty_package_skipped);
    TEST_REGISTER_ID("-", test_ac_happy_path_single_image);
    TEST_REGISTER_ID("-", test_ac_finalize_boot_noop_idle);
    TEST_REGISTER_ID("-", test_ac_finalize_boot_noop_active);
}
