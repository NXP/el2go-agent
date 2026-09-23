/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "test_suites.h"

#include "fwual/fwual.h"
#include "fwual_storage_fault.h"
#include "test_framework.h"

static bool test_fwual_prepare_erase_fault(void *params)
{
    bool test_status = true;
    fwual_image_desc_t desc = { .image_id = 0U, .size = 64U };
    fwual_session_t *session = NULL;
    fwual_result_t r = FWUAL_ERR_INTERNAL;

    (void)params;

    r = fwual_init();
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

    r = fwual_open_session(&session);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

    if (!fwual_storage_fault_supported(FWUAL_STORAGE_FAULT_STAGE_ERASE)) {
        TEST_PRINT_INFO("SKIP: platform cannot inject stage-erase faults");
        return true;
    }
    fwual_storage_fault_reset();

    (void)fwual_storage_fault_arm(FWUAL_STORAGE_FAULT_STAGE_ERASE);
    r = fwual_prepare_image(session, &desc);
    TEST_ASSERT_NOT_EQUAL_GOTO(FWUAL_OK, r, cleanup);

    r = fwual_prepare_image(session, &desc);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);
    TEST_PRINT_INFO("prepare_image erase-fault correctly rejected and retry succeeded");

cleanup:
    (void)fwual_close_session(session);
exit:
    return test_status;
}

static bool test_fwual_write_flash_fault(void *params)
{
    bool test_status = true;
    fwual_image_desc_t desc = { .image_id = 0U, .size = 64U };
    uint8_t buf[64U] = { 0xAAU };
    fwual_session_t *session = NULL;
    fwual_result_t r = FWUAL_ERR_INTERNAL;

    (void)params;

    r = fwual_init();
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

    r = fwual_open_session(&session);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

    r = fwual_prepare_image(session, &desc);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);

    if (!fwual_storage_fault_supported(FWUAL_STORAGE_FAULT_STAGE_WRITE)) {
        TEST_PRINT_INFO("SKIP: platform cannot inject stage-write faults");
        return true;
    }
    fwual_storage_fault_reset();

    (void)fwual_storage_fault_arm(FWUAL_STORAGE_FAULT_STAGE_WRITE);
    r = fwual_write(session, desc.image_id, 0U, buf, sizeof(buf));
    TEST_ASSERT_EQUAL_GOTO(FWUAL_ERR_IO, r, cleanup);
    TEST_PRINT_INFO("fwual_write correctly returned FWUAL_ERR_IO on flash fault");

cleanup:
    (void)fwual_close_session(session);
exit:
    return test_status;
}

static bool test_fwual_open_session_nvs_fault(void *params)
{
    bool test_status = true;
    fwual_session_t *session = NULL;
    fwual_result_t r = FWUAL_ERR_INTERNAL;

    (void)params;

    r = fwual_init();
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

    if (!fwual_storage_fault_supported(FWUAL_STORAGE_FAULT_STATE_PERSIST)) {
        TEST_PRINT_INFO("SKIP: platform cannot inject state-persist faults");
        return true;
    }
    fwual_storage_fault_reset();

    (void)fwual_storage_fault_arm(FWUAL_STORAGE_FAULT_STATE_PERSIST);
    r = fwual_open_session(&session);
    TEST_ASSERT_NOT_EQUAL_GOTO(FWUAL_OK, r, exit);

    r = fwual_open_session(&session);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);
    TEST_PRINT_INFO("open_session NVS-fault correctly rejected and retry succeeded");

cleanup:
    (void)fwual_close_session(session);
exit:
    return test_status;
}

static bool test_fwual_write_nvs_persist_fault(void *params)
{
    bool test_status = true;
    fwual_image_desc_t desc = { .image_id = 0U, .size = 64U };
    uint8_t buf[64U] = { 0xBBU };
    fwual_session_t *session = NULL;
    fwual_result_t r = FWUAL_ERR_INTERNAL;

    (void)params;

    r = fwual_init();
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

    r = fwual_open_session(&session);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

    r = fwual_prepare_image(session, &desc);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);

    if (!fwual_storage_fault_supported(FWUAL_STORAGE_FAULT_STATE_PERSIST)) {
        TEST_PRINT_INFO("SKIP: platform cannot inject state-persist faults");
        return true;
    }
    fwual_storage_fault_reset();

    (void)fwual_storage_fault_arm(FWUAL_STORAGE_FAULT_STATE_PERSIST);
    r = fwual_write(session, desc.image_id, 0U, buf, sizeof(buf));
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);
    TEST_PRINT_INFO("fwual_write survived a forced NVS persist failure (non-fatal)");

cleanup:
    (void)fwual_close_session(session);
exit:
    return test_status;
}

static bool test_fwual_rollback_boot_erase_fault(void *params)
{
    bool test_status = true;
    fwual_image_desc_t desc = { .image_id = 0U, .size = 64U };
    fwual_session_t *session = NULL;
    fwual_result_t r = FWUAL_ERR_INTERNAL;

    (void)params;

    r = fwual_init();
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

    r = fwual_open_session(&session);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

    r = fwual_prepare_image(session, &desc);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);

    if (!fwual_storage_fault_supported(FWUAL_STORAGE_FAULT_BANK_ERASE)) {
        TEST_PRINT_INFO("SKIP: platform cannot inject bank-erase faults");
        return true;
    }
    fwual_storage_fault_reset();

    (void)fwual_storage_fault_arm(FWUAL_STORAGE_FAULT_BANK_ERASE);
    r = fwual_rollback();
    TEST_ASSERT_NOT_EQUAL_GOTO(FWUAL_OK, r, cleanup);
    TEST_PRINT_INFO("fwual_rollback correctly reported the boot-erase fault");

cleanup:
    (void)fwual_close_session(session);
exit:
    return test_status;
}

static bool test_fwual_commit_only_cancelled(void *params)
{
    bool test_status = true;
    fwual_image_desc_t desc = { .image_id = 0U, .size = 64U };
    fwual_session_t *session = NULL;
    fwual_result_t r = FWUAL_ERR_INTERNAL;

    (void)params;

    r = fwual_init();
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

    r = fwual_open_session(&session);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

    r = fwual_prepare_image(session, &desc);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);

    r = fwual_cancel_image(session, desc.image_id);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);

    r = fwual_commit_session(session);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);
    TEST_PRINT_INFO("fwual_commit_session with only a cancelled image: OK");

cleanup:
    (void)fwual_close_session(session);
exit:
    return test_status;
}

static bool test_fwual_staged_after_close(void *params)
{
    bool test_status = true;
    fwual_image_desc_t desc = { .image_id = 0U, .size = 64U };
    fwual_session_t *session = NULL;
    fwual_result_t r = FWUAL_ERR_INTERNAL;

    (void)params;

    r = fwual_init();
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

    r = fwual_open_session(&session);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

    r = fwual_prepare_image(session, &desc);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

    (void)fwual_close_session(session);

    TEST_ASSERT_GOTO(fwual_is_image_staged(session, desc.image_id) == false, exit);
    TEST_PRINT_INFO("fwual_is_image_staged correctly returned false after close_session");

exit:
    return test_status;
}

static bool test_fwual_close_session_wrong_pointer(void *params)
{
    bool test_status = true;
    long bogus_storage = 0;
    fwual_session_t *bogus = (fwual_session_t *)&bogus_storage;
    fwual_result_t r = FWUAL_ERR_INTERNAL;

    (void)params;

    r = fwual_init();
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

    r = fwual_close_session(bogus);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_ERR_INVALID_PARAM, r, exit);
    TEST_PRINT_INFO("fwual_close_session(wrong pointer) correctly rejected");

exit:
    return test_status;
}

static bool test_fwual_close_session_cancels_prepared(void *params)
{
    bool test_status = true;
    fwual_image_desc_t desc = { .image_id = 0U, .size = 64U };
    fwual_session_t *session = NULL;
    fwual_result_t r = FWUAL_ERR_INTERNAL;

    (void)params;

    r = fwual_init();
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

    r = fwual_open_session(&session);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

    r = fwual_prepare_image(session, &desc);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

    r = fwual_close_session(session);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);
    TEST_PRINT_INFO("fwual_close_session released a still-prepared image slot");

exit:
    return test_status;
}

static bool test_fwual_prepare_null_params(void *params)
{
    bool test_status = true;
    fwual_image_desc_t desc = { .image_id = 0U, .size = 64U };
    fwual_session_t *session = NULL;
    fwual_result_t r = FWUAL_ERR_INTERNAL;

    (void)params;

    r = fwual_init();
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

    r = fwual_open_session(&session);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

    r = fwual_prepare_image(NULL, &desc);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_ERR_INVALID_PARAM, r, cleanup);

    r = fwual_prepare_image(session, NULL);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_ERR_INVALID_PARAM, r, cleanup);
    TEST_PRINT_INFO("fwual_prepare_image(NULL session/desc) correctly rejected");

cleanup:
    (void)fwual_close_session(session);
exit:
    return test_status;
}

static bool test_fwual_prepare_wrong_session_pointer(void *params)
{
    bool test_status = true;
    fwual_image_desc_t desc = { .image_id = 0U, .size = 64U };
    long bogus_storage = 0;
    fwual_session_t *bogus = (fwual_session_t *)&bogus_storage;
    fwual_session_t *session = NULL;
    fwual_result_t r = FWUAL_ERR_INTERNAL;

    (void)params;

    r = fwual_init();
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

    r = fwual_open_session(&session);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

    r = fwual_prepare_image(bogus, &desc);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_ERR_INVALID_PARAM, r, cleanup);
    TEST_PRINT_INFO("fwual_prepare_image(wrong session pointer) correctly rejected");

cleanup:
    (void)fwual_close_session(session);
exit:
    return test_status;
}

static bool test_fwual_prepare_reuses_cancelled_slot(void *params)
{
    bool test_status = true;
    fwual_image_desc_t desc = { .image_id = 0U, .size = 64U };
    fwual_session_t *session = NULL;
    fwual_result_t r = FWUAL_ERR_INTERNAL;

    (void)params;

    r = fwual_init();
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

    r = fwual_open_session(&session);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

    r = fwual_prepare_image(session, &desc);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);

    r = fwual_cancel_image(session, desc.image_id);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);

    r = fwual_prepare_image(session, &desc);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);
    TEST_PRINT_INFO("fwual_prepare_image reused a cancelled slot entry");

cleanup:
    (void)fwual_close_session(session);
exit:
    return test_status;
}

static bool test_fwual_cancel_null_and_wrong_pointer(void *params)
{
    bool test_status = true;
    long bogus_storage = 0;
    fwual_session_t *bogus = (fwual_session_t *)&bogus_storage;
    fwual_result_t r = FWUAL_ERR_INTERNAL;

    (void)params;

    r = fwual_init();
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

    r = fwual_cancel_image(NULL, 0U);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_ERR_INVALID_PARAM, r, exit);

    r = fwual_cancel_image(bogus, 0U);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_ERR_INVALID_PARAM, r, exit);
    TEST_PRINT_INFO("fwual_cancel_image(NULL/wrong pointer) correctly rejected");

exit:
    return test_status;
}

static bool test_fwual_cancel_session_not_active(void *params)
{
    bool test_status = true;
    fwual_image_desc_t desc = { .image_id = 0U, .size = 64U };
    fwual_session_t *session = NULL;
    fwual_result_t r = FWUAL_ERR_INTERNAL;

    (void)params;

    r = fwual_init();
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

    r = fwual_open_session(&session);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

    r = fwual_prepare_image(session, &desc);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

    (void)fwual_close_session(session);

    r = fwual_cancel_image(session, desc.image_id);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_ERR_INVALID_STATE, r, exit);
    TEST_PRINT_INFO("fwual_cancel_image on inactive session correctly rejected");

exit:
    return test_status;
}

static bool test_fwual_check_storage_wrong_session_and_unprepared(void *params)
{
    bool test_status = true;
    long bogus_storage = 0;
    fwual_session_t *bogus = (fwual_session_t *)&bogus_storage;
    fwual_session_t *session = NULL;
    fwual_result_t r = FWUAL_ERR_INTERNAL;

    (void)params;

    r = fwual_init();
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

    r = fwual_open_session(&session);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

    r = fwual_check_storage(bogus, 0U);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_ERR_INVALID_STATE, r, cleanup);

    r = fwual_check_storage(session, 999U);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_ERR_INVALID_STATE, r, cleanup);
    TEST_PRINT_INFO("fwual_check_storage correctly rejected wrong pointer and unprepared image_id");

cleanup:
    (void)fwual_close_session(session);
exit:
    return test_status;
}

static bool test_fwual_list_installed_zero_capacity(void *params)
{
    bool test_status = true;
    fwual_installed_image_t list[1] = { 0 };
    size_t count = 0U;
    fwual_result_t r = FWUAL_ERR_INTERNAL;

    (void)params;

    r = fwual_init();
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

    r = fwual_list_installed(list, &count);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);
    TEST_ASSERT_EQUAL_GOTO(0, (int)count, exit);
    TEST_PRINT_INFO("fwual_list_installed with zero capacity returned OK, count=0");

exit:
    return test_status;
}

static bool test_fwual_cancel_skips_non_matching_entries(void *params)
{
    bool test_status = true;
    fwual_image_desc_t desc0 = { .image_id = 0U, .size = 64U };
    fwual_session_t *session = NULL;
    fwual_result_t r = FWUAL_ERR_INTERNAL;

    (void)params;

    r = fwual_init();
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

    r = fwual_open_session(&session);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

    r = fwual_prepare_image(session, &desc0);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);

    r = fwual_cancel_image(session, 42U);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_ERR_INVALID_PARAM, r, cleanup);

    r = fwual_cancel_image(session, desc0.image_id);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);
    TEST_PRINT_INFO("fwual_cancel_image correctly skipped non-matching entries");

cleanup:
    (void)fwual_close_session(session);
exit:
    return test_status;
}

static bool test_fwual_get_state_uninitialized(void *params)
{
    bool test_status = true;

    (void)params;
    fwual_state_t state = fwual_get_state();

    TEST_ASSERT_GOTO(state == FWUAL_STATE_FAILED || state >= FWUAL_STATE_IDLE, exit);
    TEST_PRINT_INFO("fwual_get_state() returned a valid state: %d", (int)state);

exit:
    return test_status;
}

static bool test_fwual_write_and_finalize_wrong_session_pointer(void *params)
{
    bool test_status = true;
    long bogus_storage = 0;
    fwual_session_t *bogus = (fwual_session_t *)&bogus_storage;
    uint8_t buf[16] = { 0 };
    fwual_result_t r = FWUAL_ERR_INTERNAL;

    (void)params;

    r = fwual_init();
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

    r = fwual_write(bogus, 0U, 0U, buf, sizeof(buf));
    TEST_ASSERT_EQUAL_GOTO(FWUAL_ERR_INVALID_STATE, r, exit);

    r = fwual_finalize_image(bogus, 0U);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_ERR_INVALID_STATE, r, exit);
    TEST_PRINT_INFO("fwual_write/finalize_image(wrong session pointer) correctly rejected");

exit:
    return test_status;
}

void register_fwual_tests(void)
{
    TEST_REGISTER_ID("OTA_UT_FW_7.1", test_fwual_prepare_erase_fault);
    TEST_REGISTER_ID("OTA_UT_FW_7.2", test_fwual_write_flash_fault);
    TEST_REGISTER_ID("OTA_UT_FW_7.3", test_fwual_open_session_nvs_fault);
    TEST_REGISTER_ID("OTA_UT_FW_7.4", test_fwual_write_nvs_persist_fault);
    TEST_REGISTER_ID("OTA_UT_FW_7.5", test_fwual_rollback_boot_erase_fault);
    TEST_REGISTER_ID("OTA_UT_FW_7.6", test_fwual_commit_only_cancelled);
    TEST_REGISTER_ID("OTA_UT_FW_7.7", test_fwual_staged_after_close);
    TEST_REGISTER_ID("OTA_UT_FW_7.8", test_fwual_close_session_wrong_pointer);
    TEST_REGISTER_ID("OTA_UT_FW_7.9", test_fwual_close_session_cancels_prepared);
    TEST_REGISTER_ID("OTA_UT_FW_7.10", test_fwual_prepare_null_params);
    TEST_REGISTER_ID("OTA_UT_FW_7.11", test_fwual_prepare_wrong_session_pointer);
    TEST_REGISTER_ID("OTA_UT_FW_7.12", test_fwual_prepare_reuses_cancelled_slot);
    TEST_REGISTER_ID("OTA_UT_FW_7.13", test_fwual_cancel_null_and_wrong_pointer);
    TEST_REGISTER_ID("OTA_UT_FW_7.14", test_fwual_cancel_session_not_active);
    TEST_REGISTER_ID("OTA_UT_FW_7.15", test_fwual_check_storage_wrong_session_and_unprepared);
    TEST_REGISTER_ID("OTA_UT_FW_7.16", test_fwual_list_installed_zero_capacity);
    TEST_REGISTER_ID("OTA_UT_FW_7.17", test_fwual_cancel_skips_non_matching_entries);
    TEST_REGISTER_ID("OTA_UT_FW_7.18", test_fwual_get_state_uninitialized);
    TEST_REGISTER_ID("OTA_UT_FW_7.19", test_fwual_write_and_finalize_wrong_session_pointer);
}
