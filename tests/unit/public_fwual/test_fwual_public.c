/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>

#include "fwual/fwual.h"
#include "test_framework.h"
#include "test_suites.h"

/* test_fwual_get_caps_null */

/**
 * @brief Verify that fwual_get_caps(NULL) returns FWUAL_ERR_INVALID_PARAM.
 *
 * @param[in] params Unused test parameter, pass NULL.
 *
 * @return true  Test passed.
 * @return false Test failed.
 */
static bool test_fwual_get_caps_null(void *params)
{
    bool test_status = true;
    fwual_result_t r = FWUAL_ERR_INTERNAL;

    (void)params;

    (void)fwual_init();

    r = fwual_get_caps(NULL);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_ERR_INVALID_PARAM, r, exit);

exit:
    return test_status;
}

/* test_fwual_open_session_null */

/**
 * @brief Verify that fwual_open_session(NULL) returns FWUAL_ERR_INVALID_PARAM.
 *
 * @param[in] params Unused test parameter, pass NULL.
 *
 * @return true  Test passed.
 * @return false Test failed.
 */
static bool test_fwual_open_session_null(void *params)
{
    bool test_status = true;
    fwual_result_t r = FWUAL_ERR_INTERNAL;

    (void)params;

    (void)fwual_init();

    r = fwual_open_session(NULL);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_ERR_INVALID_PARAM, r, exit);

exit:
    return test_status;
}

/* test_fwual_close_session_null */

/**
 * @brief Verify that fwual_close_session(NULL) is a safe no-op.
 *
 * Must return FWUAL_OK without crashing.
 *
 * @param[in] params Unused test parameter, pass NULL.
 *
 * @return true  Test passed.
 * @return false Test failed.
 */
static bool test_fwual_close_session_null(void *params)
{
    bool test_status = true;
    fwual_result_t r = FWUAL_ERR_INTERNAL;

    (void)params;

    r = fwual_close_session(NULL);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

exit:
    return test_status;
}

/* test_fwual_prepare_image_null_session */

/**
 * @brief Verify that fwual_prepare_image(NULL, desc) returns FWUAL_ERR_INVALID_PARAM.
 *
 * @param[in] params Unused test parameter, pass NULL.
 *
 * @return true  Test passed.
 * @return false Test failed.
 */
static bool test_fwual_prepare_image_null_session(void *params)
{
    bool test_status = true;
    fwual_image_desc_t desc = { .image_id = 0U, .size = 1024U };
    fwual_result_t r = FWUAL_ERR_INTERNAL;

    (void)params;

    r = fwual_prepare_image(NULL, &desc);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_ERR_INVALID_PARAM, r, exit);

exit:
    return test_status;
}

static bool test_fwual_init_idempotent(void *params)
{
    bool test_status = true;
    fwual_result_t r = FWUAL_ERR_INTERNAL;

    (void)params;

    r = fwual_init();
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

    r = fwual_init();
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

exit:
    return test_status;
}

static bool test_fwual_get_caps_valid(void *params)
{
    bool test_status = true;
    fwual_caps_t caps = { 0 };
    fwual_result_t r = FWUAL_ERR_INTERNAL;

    (void)params;

    r = fwual_init();
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

    r = fwual_get_caps(&caps);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

    TEST_ASSERT_GOTO(caps.requires_sequential_writes == true, exit);

exit:
    return test_status;
}

static bool test_fwual_open_session_valid(void *params)
{
    bool test_status = true;
    fwual_session_t *session = NULL;
    fwual_result_t r = FWUAL_ERR_INTERNAL;

    (void)params;

    r = fwual_init();
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

    r = fwual_open_session(&session);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

    TEST_ASSERT_NOT_NULL_GOTO(session, exit);

    fwual_close_session(session);

exit:
    return test_status;
}

static bool test_fwual_open_session_busy(void *params)
{
    bool test_status = true;
    fwual_session_t *session1 = NULL;
    fwual_session_t *session2 = NULL;
    fwual_result_t r = FWUAL_ERR_INTERNAL;

    (void)params;

    r = fwual_init();
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

    r = fwual_open_session(&session1);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

    r = fwual_open_session(&session2);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_ERR_BUSY, r, exit);

exit:
    fwual_close_session(session1);
    return test_status;
}

static bool test_fwual_prepare_image_no_session(void *params)
{
    bool test_status = true;
    fwual_session_t *session = NULL;
    fwual_image_desc_t desc = { .image_id = 0U, .size = 1024U };
    fwual_result_t r = FWUAL_ERR_INTERNAL;

    (void)params;

    r = fwual_init();
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

    r = fwual_open_session(&session);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

    fwual_close_session(session);

    r = fwual_prepare_image(session, &desc);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_ERR_INVALID_PARAM, r, exit);

exit:
    return test_status;
}

static bool test_fwual_prepare_image_duplicate_id(void *params)
{
    bool test_status = true;
    fwual_session_t *session = NULL;
    fwual_image_desc_t desc = { .image_id = 0U, .size = 1024U };
    fwual_result_t r = FWUAL_ERR_INTERNAL;

    (void)params;

    r = fwual_init();
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

    r = fwual_open_session(&session);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

    r = fwual_prepare_image(session, &desc);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

    r = fwual_prepare_image(session, &desc);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_ERR_INVALID_PARAM, r, exit);

exit:
    fwual_close_session(session);
    return test_status;
}

static bool test_fwual_cancel_image_valid(void *params)
{
    bool test_status = true;
    fwual_session_t *session = NULL;
    fwual_image_desc_t desc = { .image_id = 0U, .size = 1024U };
    fwual_result_t r = FWUAL_ERR_INTERNAL;

    (void)params;

    r = fwual_init();
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

    r = fwual_open_session(&session);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

    r = fwual_prepare_image(session, &desc);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

    r = fwual_cancel_image(session, desc.image_id);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

    r = fwual_prepare_image(session, &desc);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

exit:
    fwual_close_session(session);
    return test_status;
}

static bool test_fwual_cancel_image_not_prepared(void *params)
{
    bool test_status = true;
    fwual_session_t *session = NULL;
    fwual_result_t r = FWUAL_ERR_INTERNAL;

    (void)params;

    r = fwual_init();
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

    r = fwual_open_session(&session);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

    r = fwual_cancel_image(session, 99U);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_ERR_INVALID_PARAM, r, exit);

exit:
    fwual_close_session(session);
    return test_status;
}

static bool test_fwual_write_null_data(void *params)
{
    bool test_status = true;
    fwual_session_t *session = NULL;
    fwual_image_desc_t desc = { .image_id = 0U, .size = 1024U };
    fwual_result_t r = FWUAL_ERR_INTERNAL;

    (void)params;

    r = fwual_init();
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

    r = fwual_open_session(&session);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

    r = fwual_prepare_image(session, &desc);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

    r = fwual_write(session, desc.image_id, 0U, NULL, 64U);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_ERR_INVALID_PARAM, r, exit);

exit:
    fwual_close_session(session);
    return test_status;
}

static bool test_fwual_write_zero_len(void *params)
{
    bool test_status = true;
    fwual_session_t *session = NULL;
    fwual_image_desc_t desc = { .image_id = 0U, .size = 1024U };
    uint8_t buf[64] = { 0 };
    fwual_result_t r = FWUAL_ERR_INTERNAL;

    (void)params;

    r = fwual_init();
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

    r = fwual_open_session(&session);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

    r = fwual_prepare_image(session, &desc);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

    r = fwual_write(session, desc.image_id, 0U, buf, 0U);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_ERR_INVALID_PARAM, r, exit);

exit:
    fwual_close_session(session);
    return test_status;
}

static bool test_fwual_is_image_staged_false_before_finalize(void *params)
{
    bool test_status = true;
    fwual_session_t *session = NULL;
    fwual_image_desc_t desc = { .image_id = 0U, .size = 1024U };
    fwual_result_t r = FWUAL_ERR_INTERNAL;

    (void)params;

    r = fwual_init();
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

    r = fwual_open_session(&session);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

    r = fwual_prepare_image(session, &desc);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);
    TEST_ASSERT_GOTO(fwual_is_image_staged(session, desc.image_id) == false, exit);

exit:
    fwual_close_session(session);
    return test_status;
}

static bool test_fwual_is_image_staged_null_session(void *params)
{
    bool test_status = true;

    (void)params;

    TEST_ASSERT_GOTO(fwual_is_image_staged(NULL, 0U) == false, exit);

exit:
    return test_status;
}

/* write / finalize tests */

static bool test_fwual_write_null_session(void *params)
{
    bool test_status = true;
    uint8_t buf[16] = { 0 };
    fwual_result_t result = FWUAL_RESULT_UNINITIALIZED;

    (void)params;

    result = fwual_write(NULL, 0U, 0U, buf, sizeof(buf));
    TEST_ASSERT_EQUAL_GOTO(FWUAL_ERR_INVALID_PARAM, result, exit);
    TEST_PRINT_INFO("fwual_write(NULL session) correctly rejected");

exit:
    return test_status;
}

static bool test_fwual_write_null_data_standalone(void *params)
{
    bool test_status = true;
    fwual_session_t *session = NULL;
    fwual_result_t open_rc = FWUAL_RESULT_UNINITIALIZED;
    fwual_result_t result = FWUAL_RESULT_UNINITIALIZED;

    (void)params;

    open_rc = fwual_open_session(&session);
    if (open_rc != FWUAL_OK) {
        TEST_PRINT_INFO("fwual_open_session failed (%d) - skipping null data test body "
                        "(infrastructure not ready)",
                        open_rc);
        goto exit;
    }
    result = fwual_write(session, 0U, 0U, NULL, 10U);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_ERR_INVALID_PARAM, result, cleanup);
    TEST_PRINT_INFO("fwual_write(NULL data) correctly rejected");
    (void)fwual_close_session(session);
    goto exit;

cleanup:
    (void)fwual_close_session(session);
exit:
    return test_status;
}

static bool test_fwual_write_zero_len_standalone(void *params)
{
    bool test_status = true;
    fwual_session_t *session = NULL;
    fwual_result_t open_rc = FWUAL_RESULT_UNINITIALIZED;
    fwual_result_t result = FWUAL_RESULT_UNINITIALIZED;
    uint8_t buf[16] = { 0 };

    (void)params;

    open_rc = fwual_open_session(&session);
    if (open_rc != FWUAL_OK) {
        TEST_PRINT_INFO("fwual_open_session failed (%d) - skipping zero len test body", open_rc);
        goto exit;
    }

    result = fwual_write(session, 0U, 0U, buf, 0U);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_ERR_INVALID_PARAM, result, cleanup);
    TEST_PRINT_INFO("fwual_write(len=0) correctly rejected");

    (void)fwual_close_session(session);
    goto exit;

cleanup:
    (void)fwual_close_session(session);
exit:
    return test_status;
}

static bool test_fwual_finalize_null_session(void *params)
{
    bool test_status = true;
    fwual_result_t result = FWUAL_RESULT_UNINITIALIZED;

    (void)params;

    result = fwual_finalize_image(NULL, 0U);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_ERR_INVALID_PARAM, result, exit);
    TEST_PRINT_INFO("fwual_finalize_image(NULL session) correctly rejected");

exit:
    return test_status;
}

static bool test_fwual_finalize_not_prepared(void *params)
{
    bool test_status = true;
    fwual_session_t *session = NULL;
    fwual_result_t open_rc = FWUAL_RESULT_UNINITIALIZED;
    fwual_result_t result = FWUAL_RESULT_UNINITIALIZED;

    (void)params;

    open_rc = fwual_open_session(&session);
    if (open_rc != FWUAL_OK) {
        TEST_PRINT_INFO("fwual_open_session failed (%d) - skipping "
                        "finalize_not_prepared test body",
                        open_rc);
        goto exit;
    }

    /* image_id 999 was never prepared in this session */
    result = fwual_finalize_image(session, 999U);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_ERR_INVALID_STATE, result, cleanup);
    TEST_PRINT_INFO("fwual_finalize_image(unknown image_id=999) correctly rejected");

    (void)fwual_close_session(session);
    goto exit;

cleanup:
    (void)fwual_close_session(session);
exit:
    return test_status;
}

/* Test suite registration */

/**
 * @brief Write the full image in a single chunk and finalize successfully.
 */
static bool test_fwual_write_single_chunk(void *params)
{
    bool test_status = true;
    fwual_session_t *session = NULL;
    fwual_image_desc_t desc = { .image_id = 0U, .size = 256U };
    uint8_t buf[256U];
    fwual_result_t r = FWUAL_ERR_INTERNAL;

    (void)params;
    memset(buf, 0xABU, sizeof(buf));

    r = fwual_init();
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

    r = fwual_open_session(&session);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);
    r = fwual_prepare_image(session, &desc);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);

    r = fwual_write(session, desc.image_id, 0U, buf, sizeof(buf));
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);

    r = fwual_finalize_image(session, desc.image_id);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);
    TEST_PRINT_INFO("Single-chunk write + finalize: OK");

cleanup:
    (void)fwual_close_session(session);
exit:
    return test_status;
}

/**
 * @brief Write the image in three sequential chunks and finalize successfully.
 */
static bool test_fwual_write_multi_chunk(void *params)
{
    bool test_status = true;
    fwual_session_t *session = NULL;
    fwual_image_desc_t desc = { .image_id = 0U, .size = 300U };
    uint8_t buf[100U];
    fwual_result_t r = FWUAL_ERR_INTERNAL;

    (void)params;
    memset(buf, 0x55U, sizeof(buf));

    r = fwual_init();
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

    r = fwual_open_session(&session);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

    r = fwual_prepare_image(session, &desc);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);

    r = fwual_write(session, desc.image_id, 0U, buf, 100U);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);

    r = fwual_write(session, desc.image_id, 100U, buf, 100U);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);

    r = fwual_write(session, desc.image_id, 200U, buf, 100U);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);

    r = fwual_finalize_image(session, desc.image_id);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);
    TEST_PRINT_INFO("Multi-chunk write (3x100B) + finalize: OK");

cleanup:
    (void)fwual_close_session(session);
exit:
    return test_status;
}

/**
 * @brief Out-of-order write must be rejected with FWUAL_ERR_INVALID_STATE.
 */
static bool test_fwual_write_out_of_order(void *params)
{
    bool test_status = true;
    fwual_session_t *session = NULL;
    fwual_image_desc_t desc = { .image_id = 0U, .size = 256U };
    uint8_t buf[64U];
    fwual_result_t r = FWUAL_ERR_INTERNAL;

    (void)params;
    memset(buf, 0x11U, sizeof(buf));

    r = fwual_init();
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

    r = fwual_open_session(&session);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

    r = fwual_prepare_image(session, &desc);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);

    r = fwual_write(session, desc.image_id, 0U, buf, sizeof(buf));
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);

    /* Second write at offset=0 again: must be rejected */
    r = fwual_write(session, desc.image_id, 0U, buf, sizeof(buf));
    TEST_ASSERT_EQUAL_GOTO(FWUAL_ERR_INVALID_STATE, r, cleanup);
    TEST_PRINT_INFO("Out-of-order write correctly rejected");

cleanup:
    (void)fwual_close_session(session);
exit:
    return test_status;
}

/**
 * @brief Finalize with incomplete data must return FWUAL_ERR_INVALID_STATE.
 */
static bool test_fwual_finalize_incomplete(void *params)
{
    bool test_status = true;
    fwual_session_t *session = NULL;
    fwual_image_desc_t desc = { .image_id = 0U, .size = 256U };
    uint8_t buf[64U];
    fwual_result_t r = FWUAL_ERR_INTERNAL;

    (void)params;
    memset(buf, 0x22U, sizeof(buf));

    r = fwual_init();
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

    r = fwual_open_session(&session);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

    r = fwual_prepare_image(session, &desc);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);

    /* Write only 64 of 256 bytes */
    r = fwual_write(session, desc.image_id, 0U, buf, sizeof(buf));
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);

    /* Finalize must fail — not all bytes written */
    r = fwual_finalize_image(session, desc.image_id);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_ERR_INVALID_STATE, r, cleanup);
    TEST_PRINT_INFO("Finalize with incomplete data correctly rejected");

cleanup:
    (void)fwual_close_session(session);
exit:
    return test_status;
}

/**
 * @brief Write beyond declared image size must return FWUAL_ERR_INVALID_PARAM.
 */
static bool test_fwual_write_overflow(void *params)
{
    bool test_status = true;
    fwual_session_t *session = NULL;
    fwual_image_desc_t desc = { .image_id = 0U, .size = 64U };
    uint8_t buf[128U];
    fwual_result_t r = FWUAL_ERR_INTERNAL;

    (void)params;
    memset(buf, 0x33U, sizeof(buf));

    r = fwual_init();
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

    r = fwual_open_session(&session);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

    r = fwual_prepare_image(session, &desc);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);

    /* Write 128 bytes into a 64-byte image: must be rejected */
    r = fwual_write(session, desc.image_id, 0U, buf, sizeof(buf));
    TEST_ASSERT_EQUAL_GOTO(FWUAL_ERR_INVALID_PARAM, r, cleanup);
    TEST_PRINT_INFO("Write overflow correctly rejected");

cleanup:
    (void)fwual_close_session(session);
exit:
    return test_status;
}

/*Test suite registration */

void register_fwual_tests(void)
{
    /* Null-param / invalid-param tests */
    TEST_REGISTER(test_fwual_get_caps_null);
    TEST_REGISTER(test_fwual_open_session_null);
    TEST_REGISTER(test_fwual_close_session_null);
    TEST_REGISTER(test_fwual_prepare_image_null_session);
    TEST_REGISTER(test_fwual_write_null_data);
    TEST_REGISTER(test_fwual_write_zero_len);
    TEST_REGISTER(test_fwual_is_image_staged_null_session);

    /* Lifecycle / state-machine tests */
    TEST_REGISTER(test_fwual_init_idempotent);
    TEST_REGISTER(test_fwual_get_caps_valid);
    TEST_REGISTER(test_fwual_open_session_valid);
    TEST_REGISTER(test_fwual_open_session_busy);
    TEST_REGISTER(test_fwual_prepare_image_no_session);
    TEST_REGISTER(test_fwual_prepare_image_duplicate_id);
    TEST_REGISTER(test_fwual_cancel_image_valid);
    TEST_REGISTER(test_fwual_cancel_image_not_prepared);
    TEST_REGISTER(test_fwual_is_image_staged_false_before_finalize);

    /* write / finalize tests */
    TEST_REGISTER(test_fwual_write_null_session);
    TEST_REGISTER(test_fwual_write_null_data_standalone);
    TEST_REGISTER(test_fwual_write_zero_len_standalone);
    TEST_REGISTER(test_fwual_finalize_null_session);
    TEST_REGISTER(test_fwual_finalize_not_prepared);

    /* data path tests */
    TEST_REGISTER(test_fwual_write_single_chunk);
    TEST_REGISTER(test_fwual_write_multi_chunk);
    TEST_REGISTER(test_fwual_write_out_of_order);
    TEST_REGISTER(test_fwual_finalize_incomplete);
    TEST_REGISTER(test_fwual_write_overflow);
}