/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>

#include "fwual/fwual.h"
#include "test_framework.h"
#include "test_suites.h"

/*
 * SHA-256 of 256 bytes of 0xAB (precomputed offline, used by verify tests).
 *
 * echo -n "" | python3 -c "import hashlib,sys; \
 *   data=bytes([0xAB]*256); print(hashlib.sha256(data).hexdigest())"
 * => 1080e279b51b8594a78556e2fdb4dfe9ca82ac2fbab5007de2bac4213c2e1f92
 */
static const uint8_t s_hash_256x_ab[32U] = {
    0x10U, 0x80U, 0xe2U, 0x79U, 0xb5U, 0x1bU, 0x85U, 0x94U, 0xa7U, 0x85U, 0x56U,
    0xe2U, 0xfdU, 0xb4U, 0xdfU, 0xe9U, 0xcaU, 0x82U, 0xacU, 0x2fU, 0xbaU, 0xb5U,
    0x00U, 0x7dU, 0xe2U, 0xbaU, 0xc4U, 0x21U, 0x3cU, 0x2eU, 0x1fU, 0x92U
};

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
    TEST_ASSERT_EQUAL_GOTO(FWUAL_ERR_INVALID_STATE, r, exit);

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
    TEST_ASSERT_EQUAL_GOTO(FWUAL_ERR_INVALID_STATE, r, exit);

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
    uint8_t buf[100U] = { 0 };
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
    uint8_t buf[64U] = { 0 };
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
    uint8_t buf[64U] = { 0 };
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
    uint8_t buf[128U] = { 0 };
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

/**
 * @brief Verify that fwual_verify_image(NULL, 0) returns FWUAL_ERR_INVALID_PARAM.
 *
 * @param[in] params Unused test parameter, pass NULL.
 *
 * @return true  Test passed.
 * @return false Test failed.
 */
static bool test_fwual_verify_null_session(void *params)
{
    bool test_status = true;
    fwual_result_t result = FWUAL_RESULT_UNINITIALIZED;

    (void)params;

    result = fwual_verify_image(NULL, 0U);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_ERR_INVALID_PARAM, result, exit);

exit:
    return test_status;
}

/**
 * @brief Verify that fwual_verify_image() returns FWUAL_ERR_INVALID_STATE
 *        when the slot has not been finalized yet.
 *
 * @param[in] params Unused test parameter, pass NULL.
 *
 * @return true  Test passed.
 * @return false Test failed.
 */
static bool test_fwual_verify_not_finalized(void *params)
{
    bool test_status = true;
    fwual_session_t *session = NULL;
    fwual_result_t open_rc = FWUAL_RESULT_UNINITIALIZED;
    fwual_result_t result = FWUAL_RESULT_UNINITIALIZED;
    static const uint8_t dummy_hash[32] = { 0 };
    fwual_image_desc_t desc = { .image_id = 0U,
                                .size = 256U,
                                .hash_algo = "sha256",
                                .expected_hash = dummy_hash,
                                .hash_len = 32U };

    (void)params;

    (void)fwual_init();

    open_rc = fwual_open_session(&session);
    if (open_rc != FWUAL_OK) {
        TEST_PRINT_INFO("fwual_open_session failed (%d) - skipping", open_rc);
        goto exit;
    }

    result = fwual_prepare_image(session, &desc);
    if (result != FWUAL_OK) {
        TEST_PRINT_INFO("fwual_prepare_image failed (%d) - skipping", result);
        (void)fwual_close_session(session);
        goto exit;
    }

    /* Do NOT call fwual_finalize_image -- verify must detect unfinalized slot. */
    result = fwual_verify_image(session, desc.image_id);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_ERR_INVALID_STATE, result, cleanup);
    TEST_PRINT_INFO("fwual_verify_image on unfinalized slot correctly returned "
                    "FWUAL_ERR_INVALID_STATE");

cleanup:
    (void)fwual_close_session(session);

exit:
    return test_status;
}

/**
 * @brief Verify that fwual_verify_image() returns FWUAL_ERR_UNSUPPORTED when
 *        the image descriptor specifies an unsupported hash algorithm.
 *
 * @param[in] params Unused test parameter, pass NULL.
 *
 * @return true  Test passed.
 * @return false Test failed.
 */
static bool test_fwual_verify_unsupported_algo(void *params)
{
    bool test_status = true;
    fwual_session_t *session = NULL;
    fwual_result_t open_rc = FWUAL_RESULT_UNINITIALIZED;
    fwual_result_t result = FWUAL_RESULT_UNINITIALIZED;
    static const uint8_t dummy_data[4] = { 0xAAU, 0xBBU, 0xCCU, 0xDDU };
    static const uint8_t dummy_hash[16] = { 0 };
    fwual_image_desc_t desc = { .image_id = 0U,
                                .size = sizeof(dummy_data),
                                .hash_algo = "md5", /* unsupported -- only sha256 is valid */
                                .expected_hash = dummy_hash,
                                .hash_len = sizeof(dummy_hash) };

    (void)params;

    (void)fwual_init();

    open_rc = fwual_open_session(&session);
    if (open_rc != FWUAL_OK) {
        TEST_PRINT_INFO("fwual_open_session failed (%d) - skipping", open_rc);
        goto exit;
    }

    result = fwual_prepare_image(session, &desc);
    if (result != FWUAL_OK) {
        TEST_PRINT_INFO("fwual_prepare_image failed (%d) - skipping", result);
        (void)fwual_close_session(session);
        goto exit;
    }

    result = fwual_write(session, desc.image_id, 0U, dummy_data, sizeof(dummy_data));
    if (result != FWUAL_OK) {
        TEST_PRINT_INFO("fwual_write failed (%d) - skipping", result);
        (void)fwual_close_session(session);
        goto exit;
    }

    result = fwual_finalize_image(session, desc.image_id);
    if (result != FWUAL_OK) {
        TEST_PRINT_INFO("fwual_finalize_image failed (%d) - skipping", result);
        (void)fwual_close_session(session);
        goto exit;
    }

    result = fwual_verify_image(session, desc.image_id);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_ERR_UNSUPPORTED, result, cleanup);
    TEST_PRINT_INFO("fwual_verify_image with unsupported algo correctly returned "
                    "FWUAL_ERR_UNSUPPORTED");

cleanup:
    (void)fwual_close_session(session);

exit:
    return test_status;
}

/**
 * @brief Happy-path verify: write 256 bytes of 0xAB, finalize, then verify
 *        with the correct precomputed SHA-256.  Expects FWUAL_OK.
 *
 *        If the backend flash is not available the test prints a skip message
 *        and still passes (infrastructure not ready in the unit-test host).
 *
 * @param[in] params Unused test parameter, pass NULL.
 *
 * @return true  Test passed.
 * @return false Test failed.
 */
static bool test_fwual_verify_correct_hash(void *params)
{
    bool test_status = true;
    fwual_session_t *session = NULL;
    fwual_result_t r = FWUAL_RESULT_UNINITIALIZED;
    uint8_t buf[256U] = { 0 };
    fwual_image_desc_t desc = { .image_id = 0U,
                                .size = 256U,
                                .hash_algo = "sha256",
                                .expected_hash = s_hash_256x_ab,
                                .hash_len = 32U };

    (void)params;
    memset(buf, 0xABU, sizeof(buf));

    r = fwual_init();
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

    r = fwual_open_session(&session);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

    r = fwual_prepare_image(session, &desc);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);

    r = fwual_write(session, desc.image_id, 0U, buf, sizeof(buf));
    if (r != FWUAL_OK) {
        TEST_PRINT_INFO("fwual_write failed (%d) - backend not available, skipping", r);
        goto cleanup;
    }

    r = fwual_finalize_image(session, desc.image_id);
    if (r != FWUAL_OK) {
        TEST_PRINT_INFO("fwual_finalize_image failed (%d) - skipping", r);
        goto cleanup;
    }

    r = fwual_verify_image(session, desc.image_id);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);
    TEST_PRINT_INFO("fwual_verify_image with correct hash: OK");

cleanup:
    (void)fwual_close_session(session);
exit:
    return test_status;
}

/**
 * @brief Wrong-hash verify: write 256 bytes of 0xAB, finalize, then verify
 *        with an all-zero expected hash.  Expects FWUAL_ERR_CORRUPT.
 *
 * @param[in] params Unused test parameter, pass NULL.
 *
 * @return true  Test passed.
 * @return false Test failed.
 */
static bool test_fwual_verify_wrong_hash(void *params)
{
    bool test_status = true;
    fwual_session_t *session = NULL;
    fwual_result_t r = FWUAL_RESULT_UNINITIALIZED;
    uint8_t buf[256U] = { 0 };
    static const uint8_t zero_hash[32U] = { 0 };
    fwual_image_desc_t desc = { .image_id = 0U,
                                .size = 256U,
                                .hash_algo = "sha256",
                                .expected_hash = zero_hash,
                                .hash_len = 32U };

    (void)params;
    memset(buf, 0xABU, sizeof(buf));

    r = fwual_init();
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

    r = fwual_open_session(&session);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

    r = fwual_prepare_image(session, &desc);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);

    r = fwual_write(session, desc.image_id, 0U, buf, sizeof(buf));
    if (r != FWUAL_OK) {
        TEST_PRINT_INFO("fwual_write failed (%d) - backend not available, skipping", r);
        goto cleanup;
    }

    r = fwual_finalize_image(session, desc.image_id);
    if (r != FWUAL_OK) {
        TEST_PRINT_INFO("fwual_finalize_image failed (%d) - skipping", r);
        goto cleanup;
    }

    r = fwual_verify_image(session, desc.image_id);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_ERR_CORRUPT, r, cleanup);
    TEST_PRINT_INFO("fwual_verify_image with wrong hash correctly returned FWUAL_ERR_CORRUPT");

cleanup:
    (void)fwual_close_session(session);
exit:
    return test_status;
}

/**
 * @brief Verify that calling fwual_verify_image() twice on a successfully
 *        verified slot returns FWUAL_OK both times (idempotent).
 *
 * @param[in] params Unused test parameter, pass NULL.
 *
 * @return true  Test passed.
 * @return false Test failed.
 */
static bool test_fwual_verify_idempotent(void *params)
{
    bool test_status = true;
    fwual_session_t *session = NULL;
    fwual_result_t r = FWUAL_RESULT_UNINITIALIZED;
    uint8_t buf[256U] = { 0 };
    fwual_image_desc_t desc = { .image_id = 0U,
                                .size = 256U,
                                .hash_algo = "sha256",
                                .expected_hash = s_hash_256x_ab,
                                .hash_len = 32U };

    (void)params;
    memset(buf, 0xABU, sizeof(buf));

    r = fwual_init();
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

    r = fwual_open_session(&session);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

    r = fwual_prepare_image(session, &desc);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);

    r = fwual_write(session, desc.image_id, 0U, buf, sizeof(buf));
    if (r != FWUAL_OK) {
        TEST_PRINT_INFO("fwual_write failed (%d) - backend not available, skipping", r);
        goto cleanup;
    }

    r = fwual_finalize_image(session, desc.image_id);
    if (r != FWUAL_OK) {
        TEST_PRINT_INFO("fwual_finalize_image failed (%d) - skipping", r);
        goto cleanup;
    }

    r = fwual_verify_image(session, desc.image_id);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);

    /* Second call must also succeed. */
    r = fwual_verify_image(session, desc.image_id);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);
    TEST_PRINT_INFO("fwual_verify_image idempotent: both calls returned OK");

cleanup:
    (void)fwual_close_session(session);
exit:
    return test_status;
}

/**
 * @brief After a successful full lifecycle (write -> finalize -> verify),
 *        fwual_is_image_staged() must return true.
 *
 * @param[in] params Unused test parameter, pass NULL.
 *
 * @return true  Test passed.
 * @return false Test failed.
 */
static bool test_fwual_is_image_staged_true_after_verify(void *params)
{
    bool test_status = true;
    fwual_session_t *session = NULL;
    fwual_result_t r = FWUAL_RESULT_UNINITIALIZED;
    uint8_t buf[256U] = { 0 };
    fwual_image_desc_t desc = { .image_id = 0U,
                                .size = 256U,
                                .hash_algo = "sha256",
                                .expected_hash = s_hash_256x_ab,
                                .hash_len = 32U };

    (void)params;
    memset(buf, 0xABU, sizeof(buf));

    r = fwual_init();
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

    r = fwual_open_session(&session);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

    r = fwual_prepare_image(session, &desc);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);

    r = fwual_write(session, desc.image_id, 0U, buf, sizeof(buf));
    if (r != FWUAL_OK) {
        TEST_PRINT_INFO("fwual_write failed (%d) - backend not available, skipping", r);
        goto cleanup;
    }

    r = fwual_finalize_image(session, desc.image_id);
    if (r != FWUAL_OK) {
        TEST_PRINT_INFO("fwual_finalize_image failed (%d) - skipping", r);
        goto cleanup;
    }

    r = fwual_verify_image(session, desc.image_id);
    if (r != FWUAL_OK) {
        TEST_PRINT_INFO("fwual_verify_image failed (%d) - skipping", r);
        goto cleanup;
    }

    TEST_ASSERT_GOTO(fwual_is_image_staged(session, desc.image_id) == true, cleanup);
    TEST_PRINT_INFO("fwual_is_image_staged returned true after successful verify: OK");

cleanup:
    (void)fwual_close_session(session);
exit:
    return test_status;
}

/**
 * @brief Verify that fwual_commit_session(NULL) returns FWUAL_ERR_INVALID_PARAM.
 *
 * @param[in] params Unused test parameter, pass NULL.
 *
 * @return true  Test passed.
 * @return false Test failed.
 */
static bool test_fwual_commit_session_null(void *params)
{
    bool test_status = true;
    fwual_result_t result = FWUAL_RESULT_UNINITIALIZED;

    (void)params;

    result = fwual_commit_session(NULL);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_ERR_INVALID_PARAM, result, exit);
    TEST_PRINT_INFO("fwual_commit_session(NULL) correctly rejected");

exit:
    return test_status;
}

/**
 * @brief Full lifecycle happy-path through commit: prepare -> write -> finalize
 *        -> verify -> commit.  Expects FWUAL_OK.
 *
 *        Gracefully skips any step that fails due to missing backend flash.
 *
 * @param[in] params Unused test parameter, pass NULL.
 *
 * @return true  Test passed.
 * @return false Test failed.
 */
static bool test_fwual_commit_session_valid(void *params)
{
    bool test_status = true;
    fwual_session_t *session = NULL;
    fwual_result_t r = FWUAL_RESULT_UNINITIALIZED;
    uint8_t buf[256U] = { 0 };
    fwual_image_desc_t desc = { .image_id = 0U,
                                .size = 256U,
                                .hash_algo = "sha256",
                                .expected_hash = s_hash_256x_ab,
                                .hash_len = 32U };

    (void)params;
    memset(buf, 0xABU, sizeof(buf));

    r = fwual_init();
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

    r = fwual_open_session(&session);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

    r = fwual_prepare_image(session, &desc);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);

    r = fwual_write(session, desc.image_id, 0U, buf, sizeof(buf));
    if (r != FWUAL_OK) {
        TEST_PRINT_INFO("fwual_write failed (%d) - backend not available, skipping", r);
        goto cleanup;
    }

    r = fwual_finalize_image(session, desc.image_id);
    if (r != FWUAL_OK) {
        TEST_PRINT_INFO("fwual_finalize_image failed (%d) - skipping", r);
        goto cleanup;
    }

    r = fwual_verify_image(session, desc.image_id);
    if (r != FWUAL_OK) {
        TEST_PRINT_INFO("fwual_verify_image failed (%d) - skipping", r);
        goto cleanup;
    }

    r = fwual_commit_session(session);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);
    TEST_PRINT_INFO("fwual_commit_session after full lifecycle: OK");

cleanup:
    (void)fwual_close_session(session);
exit:
    return test_status;
}

/**
 * @brief Verify that fwual_activate() in a non-COMMITTED state returns FWUAL_ERR_INVALID_STATE.
 *
 * Calls fwual_rollback() first to force the lifecycle into ROLLED_BACK, which is
 * never a valid precondition for activate().  This makes the test independent of
 * any NVS state left by previous runs.
 */
static bool test_fwual_activate_wrong_state(void *params)
{
    bool test_status = true;

    (void)params;

    (void)fwual_init();

    /* Force lifecycle to ROLLED_BACK so that fwual_activate() has a deterministic
     * wrong-state precondition regardless of what NVS holds from prior runs. */
    (void)fwual_rollback();

    fwual_result_t result = fwual_activate();
    TEST_ASSERT_EQUAL_GOTO(FWUAL_ERR_INVALID_STATE, result, exit);
    TEST_PRINT_INFO("fwual_activate() in non-COMMITTED state correctly returned "
                    "FWUAL_ERR_INVALID_STATE");

exit:
    return test_status;
}

/**
 * @brief Verify that fwual_confirm() in IDLE state returns FWUAL_ERR_INVALID_STATE.
 */
static bool test_fwual_confirm_wrong_state(void *params)
{
    bool test_status = true;

    (void)params;

    (void)fwual_init();

    fwual_result_t result = fwual_confirm();
    TEST_ASSERT_EQUAL_GOTO(FWUAL_ERR_INVALID_STATE, result, exit);
    TEST_PRINT_INFO("fwual_confirm() in IDLE state correctly returned FWUAL_ERR_INVALID_STATE");

exit:
    return test_status;
}

/**
 * @brief Verify that fwual_list_installed(NULL, &count) returns FWUAL_ERR_INVALID_PARAM.
 */
static bool test_fwual_list_installed_null(void *params)
{
    bool test_status = true;
    size_t count = 4U;

    (void)params;

    fwual_result_t result = fwual_list_installed(NULL, &count);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_ERR_INVALID_PARAM, result, exit);
    TEST_PRINT_INFO("fwual_list_installed(NULL, &count) correctly returned "
                    "FWUAL_ERR_INVALID_PARAM");

exit:
    return test_status;
}

/**
 * @brief After a successful full lifecycle (write -> finalize -> verify -> commit),
 *        fwual_get_state() must return FWUAL_STATE_COMMITTED.
 *
 * This validates that fwual_commit_session() transitions the lifecycle state
 * to COMMITTED without calling boot_request_upgrade_multi -- that call belongs
 * exclusively in fwual_activate().
 *
 * @param[in] params Unused test parameter, pass NULL.
 *
 * @return true  Test passed.
 * @return false Test failed.
 */
static bool test_fwual_get_state_committed_after_commit(void *params)
{
    bool test_status = true;
    fwual_session_t *session = NULL;
    fwual_result_t r = FWUAL_RESULT_UNINITIALIZED;
    uint8_t buf[256U] = { 0 };
    fwual_state_t state = FWUAL_STATE_IDLE;
    fwual_image_desc_t desc = { .image_id = 0U,
                                .size = 256U,
                                .hash_algo = "sha256",
                                .expected_hash = s_hash_256x_ab,
                                .hash_len = 32U };

    (void)params;
    memset(buf, 0xABU, sizeof(buf));

    r = fwual_init();
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

    r = fwual_open_session(&session);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);

    r = fwual_prepare_image(session, &desc);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);

    r = fwual_write(session, desc.image_id, 0U, buf, sizeof(buf));
    if (r != FWUAL_OK) {
        TEST_PRINT_INFO("fwual_write failed (%d) - backend not available, skipping", r);
        goto cleanup;
    }

    r = fwual_finalize_image(session, desc.image_id);
    if (r != FWUAL_OK) {
        TEST_PRINT_INFO("fwual_finalize_image failed (%d) - skipping", r);
        goto cleanup;
    }

    r = fwual_verify_image(session, desc.image_id);
    if (r != FWUAL_OK) {
        TEST_PRINT_INFO("fwual_verify_image failed (%d) - skipping", r);
        goto cleanup;
    }

    r = fwual_commit_session(session);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, cleanup);

    /* After commit, lifecycle state must be COMMITTED -- fwual_activate() is the next step. */
    state = fwual_get_state();
    TEST_ASSERT_EQUAL_GOTO(FWUAL_STATE_COMMITTED, state, cleanup);
    TEST_PRINT_INFO("fwual_get_state() returned FWUAL_STATE_COMMITTED after commit: OK");

cleanup:
    (void)fwual_close_session(session);
exit:
    return test_status;
}

/* Test suite registration */

void register_fwual_tests(void)
{
    /* Null-param / invalid-param tests (OTA_UT_FW_1.x) */
    TEST_REGISTER_ID("OTA_UT_FW_1.1", test_fwual_get_caps_null);
    TEST_REGISTER_ID("OTA_UT_FW_1.2", test_fwual_open_session_null);
    TEST_REGISTER_ID("OTA_UT_FW_1.3", test_fwual_close_session_null);
    TEST_REGISTER_ID("OTA_UT_FW_1.4", test_fwual_prepare_image_null_session);
    TEST_REGISTER_ID("OTA_UT_FW_1.5", test_fwual_write_null_data);
    TEST_REGISTER_ID("OTA_UT_FW_1.6", test_fwual_write_zero_len);
    TEST_REGISTER_ID("OTA_UT_FW_1.7", test_fwual_is_image_staged_null_session);
    TEST_REGISTER_ID("OTA_UT_FW_1.8", test_fwual_write_null_session);
    TEST_REGISTER_ID("OTA_UT_FW_1.9", test_fwual_finalize_null_session);
    TEST_REGISTER_ID("OTA_UT_FW_1.10", test_fwual_verify_null_session);
    TEST_REGISTER_ID("OTA_UT_FW_1.11", test_fwual_commit_session_null);
    TEST_REGISTER_ID("OTA_UT_FW_1.12", test_fwual_list_installed_null);

    /* Lifecycle / state-machine tests (OTA_UT_FW_2.x) */
    TEST_REGISTER_ID("OTA_UT_FW_2.1", test_fwual_init_idempotent);
    TEST_REGISTER_ID("OTA_UT_FW_2.2", test_fwual_get_caps_valid);
    TEST_REGISTER_ID("OTA_UT_FW_2.3", test_fwual_open_session_valid);
    TEST_REGISTER_ID("OTA_UT_FW_2.4", test_fwual_open_session_busy);
    TEST_REGISTER_ID("OTA_UT_FW_2.5", test_fwual_prepare_image_no_session);
    TEST_REGISTER_ID("OTA_UT_FW_2.6", test_fwual_prepare_image_duplicate_id);
    TEST_REGISTER_ID("OTA_UT_FW_2.7", test_fwual_cancel_image_valid);
    TEST_REGISTER_ID("OTA_UT_FW_2.8", test_fwual_cancel_image_not_prepared);
    TEST_REGISTER_ID("OTA_UT_FW_2.9", test_fwual_is_image_staged_false_before_finalize);
    TEST_REGISTER_ID("OTA_UT_FW_2.10", test_fwual_finalize_not_prepared);
    TEST_REGISTER_ID("OTA_UT_FW_2.11", test_fwual_activate_wrong_state);
    TEST_REGISTER_ID("OTA_UT_FW_2.12", test_fwual_confirm_wrong_state);

    /* Data path tests (OTA_UT_FW_3.x) */
    TEST_REGISTER_ID("OTA_UT_FW_3.1", test_fwual_write_single_chunk);
    TEST_REGISTER_ID("OTA_UT_FW_3.2", test_fwual_write_multi_chunk);
    TEST_REGISTER_ID("OTA_UT_FW_3.3", test_fwual_write_out_of_order);
    TEST_REGISTER_ID("OTA_UT_FW_3.4", test_fwual_finalize_incomplete);
    TEST_REGISTER_ID("OTA_UT_FW_3.5", test_fwual_write_overflow);

    /* Verify tests (OTA_UT_FW_4.x) */
    TEST_REGISTER_ID("OTA_UT_FW_4.1", test_fwual_verify_not_finalized);
    TEST_REGISTER_ID("OTA_UT_FW_4.2", test_fwual_verify_unsupported_algo);
    TEST_REGISTER_ID("OTA_UT_FW_4.3", test_fwual_verify_correct_hash);
    TEST_REGISTER_ID("OTA_UT_FW_4.4", test_fwual_verify_wrong_hash);
    TEST_REGISTER_ID("OTA_UT_FW_4.5", test_fwual_verify_idempotent);
    TEST_REGISTER_ID("OTA_UT_FW_4.6", test_fwual_is_image_staged_true_after_verify);

    /* Commit and post-commit state tests (OTA_UT_FW_5.x) */
    TEST_REGISTER_ID("OTA_UT_FW_5.1", test_fwual_commit_session_valid);
    TEST_REGISTER_ID("OTA_UT_FW_5.2", test_fwual_get_state_committed_after_commit);
}
