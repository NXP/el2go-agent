/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "fwual/fwual.h"
#include "test_framework.h"
#include "test_suites.h"

/* -------------------------------------------------------------------------
 * test_fwual_get_caps_null
 * ---------------------------------------------------------------------- */

/**
 * @brief Verify that fwual_get_caps(NULL) returns FWUAL_ERR_INVALID_PARAM.
 *
 * @param[in] params Unused test parameter, pass NULL.
 *
 * @retval true  Test passed.
 * @retval false Test failed.
 */
static bool test_fwual_get_caps_null(void *params)
{
    bool test_status = true;
    fwual_result_t r;

    (void)params;

    fwual_init();

    r = fwual_get_caps(NULL);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_ERR_INVALID_PARAM, r, exit);

exit:
    return test_status;
}

/* -------------------------------------------------------------------------
 * test_fwual_open_session_null
 * ---------------------------------------------------------------------- */

/**
 * @brief Verify that fwual_open_session(NULL) returns FWUAL_ERR_INVALID_PARAM.
 *
 * @param[in] params Unused test parameter, pass NULL.
 *
 * @retval true  Test passed.
 * @retval false Test failed.
 */
static bool test_fwual_open_session_null(void *params)
{
    bool test_status = true;
    fwual_result_t r;

    (void)params;

    fwual_init();

    r = fwual_open_session(NULL);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_ERR_INVALID_PARAM, r, exit);

exit:
    return test_status;
}

/* -------------------------------------------------------------------------
 * test_fwual_close_session_null
 * ---------------------------------------------------------------------- */

/**
 * @brief Verify that fwual_close_session(NULL) is a safe no-op.
 *
 * Must return FWUAL_OK without crashing.
 *
 * @param[in] params Unused test parameter, pass NULL.
 *
 * @retval true  Test passed.
 * @retval false Test failed.
 */
static bool test_fwual_close_session_null(void *params)
{
    bool test_status = true;
    fwual_result_t r;

    (void)params;

    r = fwual_close_session(NULL);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

exit:
    return test_status;
}

/* -------------------------------------------------------------------------
 * test_fwual_prepare_image_null_session
 * ---------------------------------------------------------------------- */

/**
 * @brief Verify that fwual_prepare_image(NULL, desc) returns FWUAL_ERR_INVALID_PARAM.
 *
 * @param[in] params Unused test parameter, pass NULL.
 *
 * @retval true  Test passed.
 * @retval false Test failed.
 */
static bool test_fwual_prepare_image_null_session(void *params)
{
    bool test_status = true;
    fwual_image_desc_t desc = { .image_id = 0U, .size = 1024U };
    fwual_result_t r;

    (void)params;

    r = fwual_prepare_image(NULL, &desc);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_ERR_INVALID_PARAM, r, exit);

exit:
    return test_status;
}

static bool test_fwual_init_idempotent(void *params)
{
    bool test_status = true;
    fwual_result_t r;
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
    fwual_result_t r;
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
    fwual_result_t r;
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
    fwual_session_t *session = NULL;
    fwual_session_t *session2 = NULL;
    fwual_result_t r;
    (void)params;
    r = fwual_init();
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);
    r = fwual_open_session(&session);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);
    r = fwual_open_session(&session2);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_ERR_BUSY, r, exit);
exit:
    fwual_close_session(session);
    return test_status;
}

static bool test_fwual_prepare_image_no_session(void *params)
{
    bool test_status = true;
    fwual_session_t *session = NULL;
    fwual_image_desc_t desc = { .image_id = 0U, .size = 1024U };
    fwual_result_t r;
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
    fwual_result_t r;
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
    fwual_result_t r;
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
    fwual_result_t r;
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
    fwual_result_t r;
    (void)params;
    r = fwual_init();
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);
    r = fwual_open_session(&session);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);
    r = fwual_prepare_image(session, &desc);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);
    r = fwual_write(session, desc.image_id, 0U, NULL, 64U);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_ERR_INTERNAL, r, exit);
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
    fwual_result_t r;
    (void)params;
    r = fwual_init();
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);
    r = fwual_open_session(&session);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);
    r = fwual_prepare_image(session, &desc);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);
    r = fwual_write(session, desc.image_id, 0U, buf, 0U);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_ERR_INTERNAL, r, exit);
exit:
    fwual_close_session(session);
    return test_status;
}

static bool test_fwual_is_image_staged_false_before_finalize(void *params)
{
    bool test_status = true;
    fwual_session_t *session = NULL;
    fwual_image_desc_t desc = { .image_id = 0U, .size = 1024U };
    fwual_result_t r;
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

/* -------------------------------------------------------------------------
 * Test suite registration
 * ---------------------------------------------------------------------- */

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
}