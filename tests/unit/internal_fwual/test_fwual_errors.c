/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

/*
 * FWUAL error-path tests (OTA_UT_FW_9.x).
 *
 * These tests need a backend that can inject faults (the Zephyr MCUboot
 * fakes). A fault that cannot be armed, or that is not consumed by the call
 * under test, is a test failure and not a skip.
 *
 * Each test arms exactly one injected fault, drives the API call that hits it
 * and always closes its session again. The library keeps its state in statics
 * that survive between tests, so every test must leave the session closed and
 * all fault knobs disarmed.
 */

#include "test_suites.h"

#include "fwual/fwual.h"
#include "fwual_storage_fault.h"
#include "test_framework.h"

#define FWUAL_TEST_IMAGE_SIZE 64U

/**
 * @brief Bytes 0x00..0x3F, matching the SHA-256 below.
 */
static const uint8_t k_fwual_test_image[FWUAL_TEST_IMAGE_SIZE] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
};

/**
 * @brief SHA-256 digest of k_fwual_test_image.
 */
static const uint8_t k_fwual_test_image_sha256[32] = {
    0xfd, 0xea, 0xb9, 0xac, 0xf3, 0x71, 0x03, 0x62, 0xbd, 0x26, 0x58, 0xcd, 0xc9, 0xa2, 0x9e, 0x8f,
    0x9c, 0x75, 0x7f, 0xcf, 0x98, 0x11, 0x60, 0x3a, 0x8c, 0x44, 0x7c, 0xd1, 0xd9, 0x15, 0x11, 0x08,
};

/**
 * @brief Populate desc with the standard test image descriptor.
 */
static void fwual_test_fill_desc(fwual_image_desc_t *desc)
{
    (void)memset(desc, 0, sizeof(*desc));
    desc->image_id = 0U;
    desc->size = FWUAL_TEST_IMAGE_SIZE;
    desc->update_type = FWUAL_UPDATE_FULL;
    desc->hash_algo = "sha256";
    desc->expected_hash = k_fwual_test_image_sha256;
    desc->hash_len = sizeof(k_fwual_test_image_sha256);
}

/**
 * @brief Open a session and prepare the standard image.
 */
static fwual_result_t fwual_test_open_prepared(fwual_session_t **session)
{
    fwual_image_desc_t desc = { 0 };
    fwual_result_t r = fwual_init();

    if (r != FWUAL_OK) {
        return r;
    }
    r = fwual_open_session(session);
    if (r != FWUAL_OK) {
        return r;
    }
    fwual_test_fill_desc(&desc);
    return fwual_prepare_image(*session, &desc);
}

/**
 * @brief Open a session and drive the standard image through write and finalize.
 */
static fwual_result_t fwual_test_stage_finalized(fwual_session_t **session)
{
    fwual_result_t r = fwual_test_open_prepared(session);

    if (r != FWUAL_OK) {
        return r;
    }
    r = fwual_write(*session, 0U, 0U, k_fwual_test_image, FWUAL_TEST_IMAGE_SIZE);
    if (r != FWUAL_OK) {
        return r;
    }
    return fwual_finalize_image(*session, 0U);
}

/**
 * @brief Open a session and drive the standard image through write, finalize and verify.
 */
static fwual_result_t fwual_test_stage_verified(fwual_session_t **session)
{
    fwual_result_t r = fwual_test_stage_finalized(session);

    if (r != FWUAL_OK) {
        return r;
    }
    return fwual_verify_image(*session, 0U);
}

/**
 * @brief NVS progress persist failures are non-fatal for write, finalize and verify.
 */
static bool test_fwual_err_progress_persist_nonfatal(void *params)
{
    bool test_status = true;
    fwual_session_t *session = NULL;
    fwual_result_t r = FWUAL_ERR_INTERNAL;

    (void)params;

    fwual_storage_fault_reset();

    r = fwual_test_open_prepared(&session);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);

    TEST_ASSERT_GOTO(fwual_storage_fault_arm(FWUAL_STORAGE_FAULT_NVS_WRITE_PROGRESS), cleanup);
    r = fwual_write(session, 0U, 0U, k_fwual_test_image, FWUAL_TEST_IMAGE_SIZE);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);
    TEST_ASSERT_GOTO(!fwual_storage_fault_pending(), cleanup);

    TEST_ASSERT_GOTO(fwual_storage_fault_arm(FWUAL_STORAGE_FAULT_NVS_WRITE_PROGRESS), cleanup);
    r = fwual_finalize_image(session, 0U);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);
    TEST_ASSERT_GOTO(!fwual_storage_fault_pending(), cleanup);

    TEST_ASSERT_GOTO(fwual_storage_fault_arm(FWUAL_STORAGE_FAULT_NVS_WRITE_PROGRESS), cleanup);
    r = fwual_verify_image(session, 0U);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);
    TEST_ASSERT_GOTO(!fwual_storage_fault_pending(), cleanup);
    TEST_PRINT_INFO("write/finalize/verify survived NVS progress persist failures");

cleanup:
    if (session != NULL) {
        TEST_ASSERT_EQUAL_CONTINUE(FWUAL_OK, fwual_close_session(session));
    }
    fwual_storage_fault_reset();
    return test_status;
}

/**
 * @brief A lifecycle persist failure in commit_session() is reported and a retry succeeds.
 */
static bool test_fwual_err_commit_lifecycle_persist_fault(void *params)
{
    bool test_status = true;
    fwual_session_t *session = NULL;
    fwual_result_t r = FWUAL_ERR_INTERNAL;

    (void)params;

    fwual_storage_fault_reset();

    r = fwual_test_stage_verified(&session);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);

    TEST_ASSERT_GOTO(fwual_storage_fault_arm(FWUAL_STORAGE_FAULT_NVS_WRITE_LIFECYCLE), cleanup);
    r = fwual_commit_session(session);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_ERR_INTERNAL, r, cleanup);
    TEST_ASSERT_GOTO(!fwual_storage_fault_pending(), cleanup);

    r = fwual_commit_session(session);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);
    TEST_PRINT_INFO("commit_session reported the lifecycle persist failure, retry succeeded");

cleanup:
    if (session != NULL) {
        TEST_ASSERT_EQUAL_CONTINUE(FWUAL_OK, fwual_close_session(session));
    }
    fwual_storage_fault_reset();
    return test_status;
}

/**
 * @brief A lifecycle persist failure in activate() is reported as FWUAL_ERR_INTERNAL.
 */
static bool test_fwual_err_activate_lifecycle_persist_fault(void *params)
{
    bool test_status = true;
    fwual_session_t *session = NULL;
    fwual_result_t r = FWUAL_ERR_INTERNAL;

    (void)params;

    fwual_storage_fault_reset();

    r = fwual_test_stage_verified(&session);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);
    r = fwual_commit_session(session);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);

    TEST_ASSERT_GOTO(fwual_storage_fault_arm(FWUAL_STORAGE_FAULT_NVS_WRITE_LIFECYCLE), cleanup);
    r = fwual_activate();
    TEST_ASSERT_EQUAL_GOTO(FWUAL_ERR_INTERNAL, r, cleanup);
    TEST_ASSERT_GOTO(!fwual_storage_fault_pending(), cleanup);
    /* NOTE: the library updates the RAM state before persisting it, so after a
     * failed persist the reported state is already the new one. */
    TEST_ASSERT_EQUAL_GOTO(FWUAL_STATE_REBOOT_REQUIRED, fwual_get_state(), cleanup);
    /* Hazard: the bootloader swap was already requested before the persist failed, so
     * it is armed while NVS still holds the old lifecycle state. */
    TEST_ASSERT_GOTO(fwual_storage_fault_boot_upgrade_pending(), cleanup);
    TEST_PRINT_INFO("activate reported the lifecycle persist failure");

cleanup:
    if (session != NULL) {
        TEST_ASSERT_EQUAL_CONTINUE(FWUAL_OK, fwual_close_session(session));
    }
    fwual_storage_fault_reset();
    return test_status;
}

/**
 * @brief A lifecycle persist failure in rollback() is reported as FWUAL_ERR_INTERNAL.
 */
static bool test_fwual_err_rollback_lifecycle_persist_fault(void *params)
{
    bool test_status = true;
    fwual_session_t *session = NULL;
    fwual_result_t r = FWUAL_ERR_INTERNAL;

    (void)params;

    fwual_storage_fault_reset();

    r = fwual_test_stage_verified(&session);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);

    TEST_ASSERT_GOTO(fwual_storage_fault_arm(FWUAL_STORAGE_FAULT_NVS_WRITE_LIFECYCLE), cleanup);
    r = fwual_rollback();
    TEST_ASSERT_EQUAL_GOTO(FWUAL_ERR_INTERNAL, r, cleanup);
    TEST_ASSERT_GOTO(!fwual_storage_fault_pending(), cleanup);
    /* NOTE: the library updates the RAM state before persisting it, so after a
     * failed persist the reported state is already the new one. */
    TEST_ASSERT_EQUAL_GOTO(FWUAL_STATE_ROLLED_BACK, fwual_get_state(), cleanup);
    TEST_PRINT_INFO("rollback reported the lifecycle persist failure");

cleanup:
    if (session != NULL) {
        TEST_ASSERT_EQUAL_CONTINUE(FWUAL_OK, fwual_close_session(session));
    }
    fwual_storage_fault_reset();
    return test_status;
}

/**
 * @brief A short NVS write of the session state makes open_session() fail, a retry succeeds.
 */
static bool test_fwual_err_open_session_short_nvs_write(void *params)
{
    bool test_status = true;
    fwual_session_t *session = NULL;
    fwual_result_t r = FWUAL_ERR_INTERNAL;

    (void)params;

    fwual_storage_fault_reset();

    r = fwual_init();
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);

    TEST_ASSERT_GOTO(fwual_storage_fault_arm(FWUAL_STORAGE_FAULT_NVS_WRITE_SHORT), cleanup);
    r = fwual_open_session(&session);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_ERR_INTERNAL, r, cleanup);
    TEST_ASSERT_GOTO(!fwual_storage_fault_pending(), cleanup);

    r = fwual_open_session(&session);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);
    TEST_PRINT_INFO("open_session rejected a short NVS state write, retry succeeded");

cleanup:
    if (session != NULL) {
        TEST_ASSERT_EQUAL_CONTINUE(FWUAL_OK, fwual_close_session(session));
    }
    fwual_storage_fault_reset();
    return test_status;
}

/**
 * @brief A short NVS write of the lifecycle state makes commit_session() fail.
 */
static bool test_fwual_err_commit_short_nvs_write(void *params)
{
    bool test_status = true;
    fwual_session_t *session = NULL;
    fwual_result_t r = FWUAL_ERR_INTERNAL;

    (void)params;

    fwual_storage_fault_reset();

    r = fwual_test_stage_verified(&session);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);

    TEST_ASSERT_GOTO(fwual_storage_fault_arm(FWUAL_STORAGE_FAULT_NVS_WRITE_SHORT), cleanup);
    r = fwual_commit_session(session);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_ERR_INTERNAL, r, cleanup);
    TEST_ASSERT_GOTO(!fwual_storage_fault_pending(), cleanup);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_STATE_COMMITTED, fwual_get_state(), cleanup);
    TEST_PRINT_INFO("commit_session rejected a short NVS lifecycle write");

cleanup:
    if (session != NULL) {
        TEST_ASSERT_EQUAL_CONTINUE(FWUAL_OK, fwual_close_session(session));
    }
    fwual_storage_fault_reset();
    return test_status;
}

/**
 * @brief A short NVS write of the write progress is non-fatal for fwual_write().
 */
static bool test_fwual_err_write_short_nvs_progress(void *params)
{
    bool test_status = true;
    fwual_session_t *session = NULL;
    fwual_result_t r = FWUAL_ERR_INTERNAL;

    (void)params;

    fwual_storage_fault_reset();

    r = fwual_test_open_prepared(&session);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);

    TEST_ASSERT_GOTO(fwual_storage_fault_arm(FWUAL_STORAGE_FAULT_NVS_WRITE_SHORT), cleanup);
    r = fwual_write(session, 0U, 0U, k_fwual_test_image, FWUAL_TEST_IMAGE_SIZE);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);
    TEST_ASSERT_GOTO(!fwual_storage_fault_pending(), cleanup);
    TEST_PRINT_INFO("write survived a short NVS progress write (non-fatal)");

cleanup:
    if (session != NULL) {
        TEST_ASSERT_EQUAL_CONTINUE(FWUAL_OK, fwual_close_session(session));
    }
    fwual_storage_fault_reset();
    return test_status;
}

/**
 * @brief A flash_area_open failure in prepare_image() is reported, a retry succeeds.
 */
static bool test_fwual_err_prepare_slot_open_fault(void *params)
{
    bool test_status = true;
    fwual_image_desc_t desc = { 0 };
    fwual_session_t *session = NULL;
    fwual_result_t r = FWUAL_ERR_INTERNAL;

    (void)params;

    fwual_storage_fault_reset();

    r = fwual_init();
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);
    r = fwual_open_session(&session);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);
    fwual_test_fill_desc(&desc);

    TEST_ASSERT_GOTO(fwual_storage_fault_arm(FWUAL_STORAGE_FAULT_SLOT_OPEN), cleanup);
    r = fwual_prepare_image(session, &desc);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_ERR_INTERNAL, r, cleanup);
    TEST_ASSERT_GOTO(!fwual_storage_fault_pending(), cleanup);

    r = fwual_prepare_image(session, &desc);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);
    TEST_PRINT_INFO("prepare_image reported the slot open failure, retry succeeded");

cleanup:
    if (session != NULL) {
        TEST_ASSERT_EQUAL_CONTINUE(FWUAL_OK, fwual_close_session(session));
    }
    fwual_storage_fault_reset();
    return test_status;
}

/**
 * @brief A flash_area_open failure in write() is reported, a retry succeeds.
 */
static bool test_fwual_err_write_slot_open_fault(void *params)
{
    bool test_status = true;
    fwual_session_t *session = NULL;
    fwual_result_t r = FWUAL_ERR_INTERNAL;

    (void)params;

    fwual_storage_fault_reset();

    r = fwual_test_open_prepared(&session);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);

    TEST_ASSERT_GOTO(fwual_storage_fault_arm(FWUAL_STORAGE_FAULT_SLOT_OPEN), cleanup);
    r = fwual_write(session, 0U, 0U, k_fwual_test_image, FWUAL_TEST_IMAGE_SIZE);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_ERR_INTERNAL, r, cleanup);
    TEST_ASSERT_GOTO(!fwual_storage_fault_pending(), cleanup);

    r = fwual_write(session, 0U, 0U, k_fwual_test_image, FWUAL_TEST_IMAGE_SIZE);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);
    TEST_PRINT_INFO("write reported the slot open failure, retry succeeded");

cleanup:
    if (session != NULL) {
        TEST_ASSERT_EQUAL_CONTINUE(FWUAL_OK, fwual_close_session(session));
    }
    fwual_storage_fault_reset();
    return test_status;
}

/**
 * @brief A flash_area_open failure while hashing makes verify_image() fail, a retry succeeds.
 */
static bool test_fwual_err_verify_slot_open_fault(void *params)
{
    bool test_status = true;
    fwual_session_t *session = NULL;
    fwual_result_t r = FWUAL_ERR_INTERNAL;

    (void)params;

    fwual_storage_fault_reset();

    r = fwual_test_stage_finalized(&session);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);

    TEST_ASSERT_GOTO(fwual_storage_fault_arm(FWUAL_STORAGE_FAULT_SLOT_OPEN), cleanup);
    r = fwual_verify_image(session, 0U);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_ERR_INTERNAL, r, cleanup);
    TEST_ASSERT_GOTO(!fwual_storage_fault_pending(), cleanup);
    TEST_ASSERT_GOTO(!fwual_is_image_staged(session, 0U), cleanup);

    r = fwual_verify_image(session, 0U);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);
    TEST_PRINT_INFO("verify_image reported the slot open failure, retry succeeded");

cleanup:
    if (session != NULL) {
        TEST_ASSERT_EQUAL_CONTINUE(FWUAL_OK, fwual_close_session(session));
    }
    fwual_storage_fault_reset();
    return test_status;
}

/**
 * @brief A flash_area_read failure while hashing makes verify_image() fail, a retry succeeds.
 */
static bool test_fwual_err_verify_slot_read_fault(void *params)
{
    bool test_status = true;
    fwual_session_t *session = NULL;
    fwual_result_t r = FWUAL_ERR_INTERNAL;

    (void)params;

    fwual_storage_fault_reset();

    r = fwual_test_stage_finalized(&session);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);

    TEST_ASSERT_GOTO(fwual_storage_fault_arm(FWUAL_STORAGE_FAULT_SLOT_READ), cleanup);
    r = fwual_verify_image(session, 0U);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_ERR_INTERNAL, r, cleanup);
    TEST_ASSERT_GOTO(!fwual_storage_fault_pending(), cleanup);
    TEST_ASSERT_GOTO(!fwual_is_image_staged(session, 0U), cleanup);

    r = fwual_verify_image(session, 0U);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);
    TEST_PRINT_INFO("verify_image reported the slot read failure, retry succeeded");

cleanup:
    if (session != NULL) {
        TEST_ASSERT_EQUAL_CONTINUE(FWUAL_OK, fwual_close_session(session));
    }
    fwual_storage_fault_reset();
    return test_status;
}

/**
 * @brief A boot_request_upgrade_multi failure in activate() is reported as FWUAL_ERR_PLATFORM.
 *
 * The lifecycle must stay COMMITTED so the caller can retry; the retry succeeds and the
 * test then rolls back to leave no pending upgrade behind.
 */
static bool test_fwual_err_activate_boot_request_fault(void *params)
{
    bool test_status = true;
    fwual_session_t *session = NULL;
    fwual_result_t r = FWUAL_ERR_INTERNAL;

    (void)params;

    fwual_storage_fault_reset();

    r = fwual_test_stage_verified(&session);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);
    r = fwual_commit_session(session);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);

    TEST_ASSERT_GOTO(fwual_storage_fault_arm(FWUAL_STORAGE_FAULT_BOOT_REQUEST), cleanup);
    r = fwual_activate();
    TEST_ASSERT_EQUAL_GOTO(FWUAL_ERR_PLATFORM, r, cleanup);
    TEST_ASSERT_GOTO(!fwual_storage_fault_pending(), cleanup);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_STATE_COMMITTED, fwual_get_state(), cleanup);
    TEST_ASSERT_GOTO(!fwual_storage_fault_boot_upgrade_pending(), cleanup);

    r = fwual_activate();
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);
    TEST_ASSERT_GOTO(fwual_storage_fault_boot_upgrade_pending(), cleanup);
    TEST_PRINT_INFO("activate reported the boot request failure, retry succeeded");

cleanup:
    (void)fwual_rollback();
    if (session != NULL) {
        TEST_ASSERT_EQUAL_CONTINUE(FWUAL_OK, fwual_close_session(session));
    }
    fwual_storage_fault_reset();
    return test_status;
}

/**
 * @brief A boot_read_bank_header failure makes list_installed() skip that slot.
 */
static bool test_fwual_err_list_installed_header_fault(void *params)
{
    bool test_status = true;
    fwual_installed_image_t list[1] = { 0 };
    size_t count = 1U;
    fwual_result_t r = FWUAL_ERR_INTERNAL;

    (void)params;

    fwual_storage_fault_reset();

    r = fwual_init();
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);

    TEST_ASSERT_GOTO(fwual_storage_fault_arm(FWUAL_STORAGE_FAULT_BOOT_HEADER), cleanup);
    r = fwual_list_installed(list, &count);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);
    TEST_ASSERT_GOTO(!fwual_storage_fault_pending(), cleanup);
    TEST_ASSERT_EQUAL_GOTO(0, (int)count, cleanup);

    count = 1U;
    r = fwual_list_installed(list, &count);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);
    TEST_ASSERT_EQUAL_GOTO(1, (int)count, cleanup);
    TEST_PRINT_INFO("list_installed skipped the slot with an unreadable header");

cleanup:
    fwual_storage_fault_reset();
    return test_status;
}

/**
 * @brief prepare_image() rejects an image_id that has no slot on this backend.
 */
static bool test_fwual_err_prepare_image_id_out_of_range(void *params)
{
    bool test_status = true;
    fwual_image_desc_t desc = { 0 };
    fwual_session_t *session = NULL;
    fwual_result_t r = FWUAL_ERR_INTERNAL;

    (void)params;

    fwual_storage_fault_reset();

    r = fwual_init();
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);
    r = fwual_open_session(&session);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);

    fwual_test_fill_desc(&desc);
    desc.image_id = 7U;
    r = fwual_prepare_image(session, &desc);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_ERR_INVALID_PARAM, r, cleanup);
    TEST_PRINT_INFO("prepare_image rejected an image_id without a slot");

cleanup:
    if (session != NULL) {
        TEST_ASSERT_EQUAL_CONTINUE(FWUAL_OK, fwual_close_session(session));
    }
    fwual_storage_fault_reset();
    return test_status;
}

/**
 * @brief prepare_image() rejects an image larger than the staging slot.
 */
static bool test_fwual_err_prepare_image_too_large(void *params)
{
    bool test_status = true;
    fwual_image_desc_t desc = { 0 };
    fwual_session_t *session = NULL;
    fwual_result_t r = FWUAL_ERR_INTERNAL;

    (void)params;

    fwual_storage_fault_reset();

    r = fwual_init();
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);
    r = fwual_open_session(&session);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);

    fwual_test_fill_desc(&desc);
    desc.size = 0x7FFFFFFFU;
    r = fwual_prepare_image(session, &desc);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_ERR_NO_SPACE, r, cleanup);

    fwual_test_fill_desc(&desc);
    r = fwual_prepare_image(session, &desc);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);
    TEST_PRINT_INFO("prepare_image rejected an oversized image, a valid one succeeded");

cleanup:
    if (session != NULL) {
        TEST_ASSERT_EQUAL_CONTINUE(FWUAL_OK, fwual_close_session(session));
    }
    fwual_storage_fault_reset();
    return test_status;
}

/**
 * @brief verify_image() and commit_session() reject a session pointer that is not the live one.
 */
static bool test_fwual_err_verify_commit_wrong_session(void *params)
{
    bool test_status = true;
    long bogus_storage = 0;
    fwual_session_t *bogus = (fwual_session_t *)&bogus_storage;
    fwual_result_t r = FWUAL_ERR_INTERNAL;

    (void)params;

    fwual_storage_fault_reset();

    r = fwual_init();
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);

    r = fwual_verify_image(bogus, 0U);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_ERR_INVALID_STATE, r, cleanup);

    r = fwual_commit_session(bogus);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_ERR_INVALID_STATE, r, cleanup);
    TEST_PRINT_INFO("verify_image/commit_session rejected a wrong session pointer");

cleanup:
    fwual_storage_fault_reset();
    return test_status;
}

/**
 * @brief activate() is blocked when a committed image was never finalized and verified.
 *
 * commit_session() only rejects images that are finalized but not verified, so a merely
 * prepared image passes it and the activate() safety gate has to catch it.
 */
static bool test_fwual_err_activate_unverified_image(void *params)
{
    bool test_status = true;
    fwual_session_t *session = NULL;
    fwual_result_t r = FWUAL_ERR_INTERNAL;

    (void)params;

    fwual_storage_fault_reset();

    r = fwual_test_open_prepared(&session);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);

    r = fwual_commit_session(session);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);

    r = fwual_activate();
    TEST_ASSERT_EQUAL_GOTO(FWUAL_ERR_INVALID_STATE, r, cleanup);
    TEST_ASSERT_GOTO(!fwual_storage_fault_boot_upgrade_pending(), cleanup);
    TEST_PRINT_INFO("activate blocked an image that was never verified");

cleanup:
    (void)fwual_rollback();
    if (session != NULL) {
        TEST_ASSERT_EQUAL_CONTINUE(FWUAL_OK, fwual_close_session(session));
    }
    fwual_storage_fault_reset();
    return test_status;
}

/**
 * @brief activate() and rollback() skip image slots that were cancelled.
 */
static bool test_fwual_err_activate_rollback_cancelled_image(void *params)
{
    bool test_status = true;
    fwual_session_t *session = NULL;
    fwual_result_t r = FWUAL_ERR_INTERNAL;

    (void)params;

    fwual_storage_fault_reset();

    r = fwual_test_open_prepared(&session);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);
    r = fwual_cancel_image(session, 0U);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);
    r = fwual_commit_session(session);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);

    /* Current behaviour: activate() with only cancelled images succeeds and moves to
     * REBOOT_REQUIRED although there is nothing to activate. Pinned here so a change
     * is noticed; whether it is intended is an open question. */
    r = fwual_activate();
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_STATE_REBOOT_REQUIRED, fwual_get_state(), cleanup);
    TEST_ASSERT_GOTO(!fwual_storage_fault_boot_upgrade_pending(), cleanup);

    r = fwual_rollback();
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_STATE_ROLLED_BACK, fwual_get_state(), cleanup);
    TEST_PRINT_INFO("activate/rollback skipped a cancelled image slot");

cleanup:
    if (session != NULL) {
        TEST_ASSERT_EQUAL_CONTINUE(FWUAL_OK, fwual_close_session(session));
    }
    fwual_storage_fault_reset();
    return test_status;
}

/**
 * @brief A state persist failure in close_session() is reported and a retry succeeds.
 */
static bool test_fwual_err_close_session_state_persist_fault(void *params)
{
    bool test_status = true;
    fwual_session_t *session = NULL;
    fwual_result_t r = FWUAL_ERR_INTERNAL;

    (void)params;

    fwual_storage_fault_reset();

    r = fwual_open_session(&session);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);

    TEST_ASSERT_GOTO(fwual_storage_fault_arm(FWUAL_STORAGE_FAULT_NVS_WRITE_STATE), cleanup);
    r = fwual_close_session(session);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_ERR_INTERNAL, r, cleanup);
    TEST_ASSERT_GOTO(!fwual_storage_fault_pending(), cleanup);

    r = fwual_close_session(session);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);
    session = NULL;
    TEST_PRINT_INFO("close_session reported the state persist failure, retry succeeded");

cleanup:
    if (session != NULL) {
        TEST_ASSERT_EQUAL_CONTINUE(FWUAL_OK, fwual_close_session(session));
    }
    fwual_storage_fault_reset();
    return test_status;
}

/**
 * @brief Persisting a value that NVS already holds (write returns 0) is treated as success.
 */
static bool test_fwual_err_nvs_write_unchanged_value(void *params)
{
    bool test_status = true;
    fwual_session_t *session = NULL;
    fwual_result_t r = FWUAL_ERR_INTERNAL;

    (void)params;

    fwual_storage_fault_reset();

    r = fwual_test_stage_verified(&session);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);

    /* The second rollback persists the same lifecycle value again. */
    r = fwual_rollback();
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);
    r = fwual_rollback();
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_STATE_ROLLED_BACK, fwual_get_state(), cleanup);
    TEST_PRINT_INFO("an unchanged NVS value (write returned 0) was accepted");

cleanup:
    if (session != NULL) {
        TEST_ASSERT_EQUAL_CONTINUE(FWUAL_OK, fwual_close_session(session));
    }
    fwual_storage_fault_reset();
    return test_status;
}

/**
 * @brief Register the FWUAL error-path tests with the test framework.
 */
void register_fwual_error_tests(void)
{
    TEST_REGISTER_ID("OTA_UT_FW_9.1", test_fwual_err_progress_persist_nonfatal);
    TEST_REGISTER_ID("OTA_UT_FW_9.2", test_fwual_err_commit_lifecycle_persist_fault);
    TEST_REGISTER_ID("OTA_UT_FW_9.3", test_fwual_err_activate_lifecycle_persist_fault);
    TEST_REGISTER_ID("OTA_UT_FW_9.4", test_fwual_err_rollback_lifecycle_persist_fault);
    TEST_REGISTER_ID("OTA_UT_FW_9.5", test_fwual_err_open_session_short_nvs_write);
    TEST_REGISTER_ID("OTA_UT_FW_9.6", test_fwual_err_commit_short_nvs_write);
    TEST_REGISTER_ID("OTA_UT_FW_9.7", test_fwual_err_write_short_nvs_progress);
    TEST_REGISTER_ID("OTA_UT_FW_9.8", test_fwual_err_prepare_slot_open_fault);
    TEST_REGISTER_ID("OTA_UT_FW_9.9", test_fwual_err_write_slot_open_fault);
    TEST_REGISTER_ID("OTA_UT_FW_9.10", test_fwual_err_verify_slot_open_fault);
    TEST_REGISTER_ID("OTA_UT_FW_9.11", test_fwual_err_verify_slot_read_fault);
    TEST_REGISTER_ID("OTA_UT_FW_9.12", test_fwual_err_activate_boot_request_fault);
    TEST_REGISTER_ID("OTA_UT_FW_9.13", test_fwual_err_list_installed_header_fault);
    TEST_REGISTER_ID("OTA_UT_FW_9.14", test_fwual_err_prepare_image_id_out_of_range);
    TEST_REGISTER_ID("OTA_UT_FW_9.15", test_fwual_err_prepare_image_too_large);
    TEST_REGISTER_ID("OTA_UT_FW_9.16", test_fwual_err_verify_commit_wrong_session);
    TEST_REGISTER_ID("OTA_UT_FW_9.17", test_fwual_err_activate_unverified_image);
    TEST_REGISTER_ID("OTA_UT_FW_9.18", test_fwual_err_activate_rollback_cancelled_image);
    TEST_REGISTER_ID("OTA_UT_FW_9.19", test_fwual_err_close_session_state_persist_fault);
    TEST_REGISTER_ID("OTA_UT_FW_9.20", test_fwual_err_nvs_write_unchanged_value);
}
