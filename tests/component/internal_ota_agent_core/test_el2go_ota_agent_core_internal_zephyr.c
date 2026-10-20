/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

/*
 * Component tests for the core OTA agent, run against the real NVS +
 * flash-simulator backend (native_sim). el2go_ota_lib and FWUAL are mocked
 * identically to the unit-level suite; only persistence is real here.
 */

#include <string.h>
#include <psa/crypto.h>

#include "test_el2go_ota_agent_core_internal_zephyr.h"

#include "agent_test_fixtures.h"
#include "el2go_ota_lib_mock.h"
#include "fwual_mock.h"
#include "wrap_app_sys.h"
#include "fwual/fwual.h"
#include "ota/el2go_ota_lib.h"

#define main el2go_ota_agent_core_main_unused
#include "el2go_ota_agent_core/src/main.c"
#undef main

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

/**
 * @brief OTA_CT_AC_1.1 : single image happy path (real NVS/flash-sim binary)
 *
 * @return @c TEST_PASS if all assertions pass, @c TEST_FAIL otherwise.
 */
static test_result_t test_ac_ct_single_image_happy_path(void)
{
    TEST_REQUIRE_CAP(CT_CAP_REAL_FLASH);
    reset_all_mocks();

    core_updater_ctx_t updater = build_test_updater();
    TEST_ASSERT_NOT_NULL(updater.ota_ctx);

    uint8_t payload[256];
    memset(payload, 0x5A, sizeof(payload));
    el2go_ota_lib_mock_set_payload(payload, sizeof(payload));

    el2go_ota_update_info_t update;
    agent_fixture_make_update_info(&update, payload, sizeof(payload));
    agent_fixture_queue_update_available(&update);

    core_updater_run_check(&updater);

    TEST_ASSERT_EQ(FWUAL_STATE_REBOOT_REQUIRED, fwual_get_state());
    TEST_ASSERT_EQ(1U, wrap_app_sys_activate_call_count());

    fwual_mock_set_lifecycle_state_for_test(FWUAL_STATE_WAITING_CONFIRM);
    core_updater_finalize_boot(&updater, FWUAL_STATE_WAITING_CONFIRM);

    TEST_ASSERT_EQ(FWUAL_STATE_ACTIVE, fwual_get_state());
    /* Success path schedules the report; report_status() is FAILURE-only. */
    TEST_ASSERT_EQ(EL2GO_OTA_OUTCOME_SUCCESS, el2go_ota_lib_mock_last_scheduled_outcome());
    TEST_ASSERT_EQ(0U, el2go_ota_lib_mock_report_call_count());
    return TEST_PASS;
}

/**
 * @brief OTA_CT_AC_1.2 : no update available, agent stays idle for 2 cycles
 *
 * @return @c TEST_PASS if all assertions pass, @c TEST_FAIL otherwise.
 */
static test_result_t test_ac_ct_no_update_stays_idle(void)
{
    TEST_REQUIRE_CAP(CT_CAP_REAL_FLASH);
    reset_all_mocks();

    core_updater_ctx_t updater = build_test_updater();
    TEST_ASSERT_NOT_NULL(updater.ota_ctx);

    agent_fixture_queue_no_update();
    agent_fixture_queue_no_update();

    core_updater_run_check(&updater);
    core_updater_run_check(&updater);

    TEST_ASSERT_EQ(2U, el2go_ota_lib_mock_check_count());
    TEST_ASSERT_EQ(0U, el2go_ota_lib_mock_download_call_count());
    TEST_ASSERT_EQ(0U, el2go_ota_lib_mock_report_call_count());
    return TEST_PASS;
}

/**
 * @brief OTA_CT_AC_1.3 : download failure -> agent reports FAILURE
 *
 * @return @c TEST_PASS if all assertions pass, @c TEST_FAIL otherwise.
 */
static test_result_t test_ac_ct_download_failure_reports_failure(void)
{
    TEST_REQUIRE_CAP(CT_CAP_REAL_FLASH);
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

    TEST_ASSERT_EQ(EL2GO_OTA_OUTCOME_FAILURE, el2go_ota_lib_mock_last_reported_outcome());
    TEST_ASSERT_NE(FWUAL_STATE_REBOOT_REQUIRED, fwual_get_state());
    return TEST_PASS;
}

/**
 * @brief OTA_CT_AC_1.4 : FWUAL handoff failure -> agent reports FAILURE
 *
 * @return @c TEST_PASS if all assertions pass, @c TEST_FAIL otherwise.
 */
static test_result_t test_ac_ct_fwual_handoff_failure(void)
{
    TEST_REQUIRE_CAP(CT_CAP_REAL_FLASH);
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

    TEST_ASSERT_EQ(EL2GO_OTA_OUTCOME_FAILURE, el2go_ota_lib_mock_last_reported_outcome());
    return TEST_PASS;
}

/**
 * @brief OTA_CT_AC_2.1 : state Idle -> Check -> Download
 *
 * @return @c TEST_PASS if all assertions pass, @c TEST_FAIL otherwise.
 */
static test_result_t test_ac_ct_state_idle_check_download(void)
{
    TEST_REQUIRE_CAP(CT_CAP_REAL_FLASH);
    reset_all_mocks();

    core_updater_ctx_t updater = build_test_updater();
    TEST_ASSERT_NOT_NULL(updater.ota_ctx);

    uint8_t payload[16] = { 0 };
    el2go_ota_lib_mock_set_payload(payload, sizeof(payload));

    el2go_ota_update_info_t update;
    agent_fixture_make_update_info(&update, payload, sizeof(payload));
    agent_fixture_queue_update_available(&update);

    TEST_ASSERT_EQ(0U, el2go_ota_lib_mock_check_count());
    TEST_ASSERT_EQ(0U, el2go_ota_lib_mock_download_call_count());

    core_updater_run_check(&updater);

    TEST_ASSERT_EQ(1U, el2go_ota_lib_mock_check_count());
    TEST_ASSERT_EQ(1U, el2go_ota_lib_mock_download_call_count());
    return TEST_PASS;
}

/**
 * @brief OTA_CT_AC_2.2 : state Download -> Install -> Reboot
 *
 * @return @c TEST_PASS if all assertions pass, @c TEST_FAIL otherwise.
 */
static test_result_t test_ac_ct_state_download_install_reboot(void)
{
    TEST_REQUIRE_CAP(CT_CAP_REAL_FLASH);
    reset_all_mocks();

    core_updater_ctx_t updater = build_test_updater();
    TEST_ASSERT_NOT_NULL(updater.ota_ctx);

    uint8_t payload[128];
    memset(payload, 0x33, sizeof(payload));
    el2go_ota_lib_mock_set_payload(payload, sizeof(payload));

    el2go_ota_update_info_t update;
    agent_fixture_make_update_info(&update, payload, sizeof(payload));
    agent_fixture_queue_update_available(&update);

    core_updater_run_check(&updater);

    TEST_ASSERT_EQ(FWUAL_STATE_REBOOT_REQUIRED, fwual_get_state());
    TEST_ASSERT_EQ(1U, wrap_app_sys_activate_call_count());
    return TEST_PASS;
}

/**
 * @brief OTA_CT_AC_2.3 : state Reboot -> Finalize -> SUCCESS
 *
 * @return @c TEST_PASS if all assertions pass, @c TEST_FAIL otherwise.
 */
static test_result_t test_ac_ct_state_reboot_finalize_success(void)
{
    TEST_REQUIRE_CAP(CT_CAP_REAL_FLASH);
    reset_all_mocks();

    core_updater_ctx_t updater = build_test_updater();
    TEST_ASSERT_NOT_NULL(updater.ota_ctx);

    fwual_mock_set_lifecycle_state_for_test(FWUAL_STATE_WAITING_CONFIRM);
    core_updater_finalize_boot(&updater, FWUAL_STATE_WAITING_CONFIRM);

    TEST_ASSERT_EQ(FWUAL_STATE_ACTIVE, fwual_get_state());
    TEST_ASSERT_EQ(EL2GO_OTA_OUTCOME_SUCCESS, el2go_ota_lib_mock_last_scheduled_outcome());
    return TEST_PASS;
}

/**
 * @brief OTA_CT_AC_2.4 : download failure -> FAILURE reported
 *
 * @return @c TEST_PASS if all assertions pass, @c TEST_FAIL otherwise.
 */
static test_result_t test_ac_ct_state_download_failure_reported(void)
{
    TEST_REQUIRE_CAP(CT_CAP_REAL_FLASH);
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

    TEST_ASSERT_EQ(EL2GO_OTA_OUTCOME_FAILURE, el2go_ota_lib_mock_last_reported_outcome());
    TEST_ASSERT_NOT_NULL(updater.ota_ctx); /* failure path does not null the context */
    return TEST_PASS;
}

TEST_SUITE_BEGIN(ota_agent_core_internal)
TEST_REGISTER("OTA_CT_AC_1.1", test_ac_ct_single_image_happy_path)
TEST_REGISTER("OTA_CT_AC_1.2", test_ac_ct_no_update_stays_idle)
TEST_REGISTER("OTA_CT_AC_1.3", test_ac_ct_download_failure_reports_failure)
TEST_REGISTER("OTA_CT_AC_1.4", test_ac_ct_fwual_handoff_failure)
TEST_REGISTER("OTA_CT_AC_2.1", test_ac_ct_state_idle_check_download)
TEST_REGISTER("OTA_CT_AC_2.2", test_ac_ct_state_download_install_reboot)
TEST_REGISTER("OTA_CT_AC_2.3", test_ac_ct_state_reboot_finalize_success)
TEST_REGISTER("OTA_CT_AC_2.4", test_ac_ct_state_download_failure_reported)
TEST_SUITE_END(ota_agent_core_internal)
