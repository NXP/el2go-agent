/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "test_fwual_public.h"

#include "fwual/fwual.h"

/**
 * @defgroup test_fwual_public Public FWUAL Component Tests
 * @brief Component tests for the public FWUAL API surface (OTA_CT_FW).
 *
 * Drives the real FWUAL backend through the public API over real flash + NVS
 * (CT_CAP_MCUBOOT). On native_sim the backend runs on the flash simulator
 * with stubbed trailer functions; on rw612 it runs on genuine MCUboot +
 * flash. Stops short of activate()+reboot and fault injection, which live in
 * the internal suite.
 *
 * @{
 */

/** image_id is also the MCUboot slot index; 0 is the only valid single-image slot. */
#define CT_FW_IMAGE_ID 0U

/** Size in bytes of the fixed test image k_fw_image[]. */
#define CT_FW_IMAGE_SIZE 64U

/** 64-byte test firmware image used as the payload for every write path. */
static const uint8_t k_fw_image[CT_FW_IMAGE_SIZE] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
};

/** Precomputed SHA-256 digest of k_fw_image, pinned as the expected hash. */
static const uint8_t k_fw_image_sha256[32] = {
    0xfd, 0xea, 0xb9, 0xac, 0xf3, 0x71, 0x03, 0x62, 0xbd, 0x26, 0x58, 0xcd, 0xc9, 0xa2, 0x9e, 0x8f,
    0x9c, 0x75, 0x7f, 0xcf, 0x98, 0x11, 0x60, 0x3a, 0x8c, 0x44, 0x7c, 0xd1, 0xd9, 0x15, 0x11, 0x08,
};

/** All-zeros SHA-256 digest, used to deliberately trigger a hash mismatch. */
static const uint8_t k_zero_sha256[32] = { 0 };

/* Helpers */

/**
 * @brief Populate desc with the standard test image descriptor
 *        (image_id, size, version, hash algo + digest).
 */
static void fill_desc(fwual_image_desc_t *desc)
{
    (void)memset(desc, 0, sizeof(*desc));
    desc->image_id = CT_FW_IMAGE_ID;
    desc->size = CT_FW_IMAGE_SIZE;
    desc->version = 1U;
    desc->update_type = FWUAL_UPDATE_FULL;
    desc->hash_algo = "sha256";
    desc->expected_hash = k_fw_image_sha256;
    desc->hash_len = sizeof(k_fw_image_sha256);
}

/**
 * @brief Write the full test image into session, honouring caps->max_write_size.
 *
 * @return FWUAL_OK on success, or the first failing fwual_write() result.
 */
static fwual_result_t write_full_image(fwual_session_t *session, const fwual_caps_t *caps)
{
    uint64_t offset = 0U;
    size_t step = caps->max_write_size;

    if (step == 0U || step > CT_FW_IMAGE_SIZE) {
        step = CT_FW_IMAGE_SIZE;
    }

    while (offset < CT_FW_IMAGE_SIZE) {
        size_t len = (size_t)(CT_FW_IMAGE_SIZE - offset);
        fwual_result_t r;

        if (len > step) {
            len = step;
        }
        r = fwual_write(session, CT_FW_IMAGE_ID, offset, &k_fw_image[offset], len);
        if (r != FWUAL_OK) {
            return r;
        }
        offset += len;
    }
    return FWUAL_OK;
}

/**
 * @brief Common test prologue: require the MCUboot-backed FWUAL capability
 *        and (re)initialise the backend.
 */
#define CT_FW_ENTER()                           \
    do {                                        \
        TEST_REQUIRE_CAP(CT_CAP_MCUBOOT);       \
        TEST_ASSERT_EQ(FWUAL_OK, fwual_init()); \
    } while (0)

/* Init and Capability Tests */

/**
 * @brief fwual_init() must be idempotent and fwual_get_caps(NULL) must reject.
 */
static test_result_t test_fw_init_and_caps(void)
{
    fwual_caps_t caps = { 0 };

    CT_FW_ENTER();
    /* Idempotent: a second init must also succeed with no side effects. */
    TEST_ASSERT_EQ(FWUAL_OK, fwual_init());

    TEST_ASSERT_EQ(FWUAL_ERR_INVALID_PARAM, fwual_get_caps(NULL));
    TEST_ASSERT_EQ(FWUAL_OK, fwual_get_caps(&caps));
    return TEST_PASS;
}

/**
 * @brief Public session/state API entry points must reject NULL parameters.
 */
static test_result_t test_fw_param_validation(void)
{
    fwual_image_desc_t desc;

    CT_FW_ENTER();
    fill_desc(&desc);

    TEST_ASSERT_EQ(FWUAL_ERR_INVALID_PARAM, fwual_open_session(NULL));
    TEST_ASSERT_EQ(FWUAL_ERR_INVALID_PARAM, fwual_prepare_image(NULL, &desc));
    TEST_ASSERT_EQ(FWUAL_ERR_INVALID_PARAM, fwual_write(NULL, CT_FW_IMAGE_ID, 0U, k_fw_image, 1U));
    TEST_ASSERT_FALSE(fwual_is_image_staged(NULL, CT_FW_IMAGE_ID));
    return TEST_PASS;
}

/**
 * @brief Opening a second concurrent session must fail with FWUAL_ERR_BUSY.
 *
 * After the first session is closed, a fresh session must open cleanly.
 */
static test_result_t test_fw_single_session_busy(void)
{
    fwual_session_t *s1 = NULL;
    fwual_session_t *s2 = NULL;

    CT_FW_ENTER();

    TEST_ASSERT_EQ(FWUAL_OK, fwual_open_session(&s1));
    TEST_ASSERT_NOT_NULL(s1);

    /* A second concurrent session must be refused. */
    TEST_ASSERT_EQ(FWUAL_ERR_BUSY, fwual_open_session(&s2));
    TEST_ASSERT_NULL(s2);

    TEST_ASSERT_EQ(FWUAL_OK, fwual_close_session(s1));

    /* After close, a fresh session opens cleanly. */
    TEST_ASSERT_EQ(FWUAL_OK, fwual_open_session(&s2));
    TEST_ASSERT_NOT_NULL(s2);
    TEST_ASSERT_EQ(FWUAL_OK, fwual_close_session(s2));
    return TEST_PASS;
}

/* Prepare / Write / Finalize Tests */

/**
 * @brief OTA_CT_FW_1.1: single-chunk prepare/write/finalize round-trip.
 *
 * Write the full image as one contiguous chunk starting at offset 0 and
 * finalize the image.
 */
static test_result_t test_fw_write_single_chunk_finalize(void)
{
    fwual_session_t *session = NULL;
    fwual_image_desc_t desc;
    test_result_t result = TEST_PASS;

    CT_FW_ENTER();
    fill_desc(&desc);

    TEST_ASSERT_EQ(FWUAL_OK, fwual_open_session(&session));
    TEST_ASSERT_NOT_NULL_GOTO(session, cleanup);

    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_prepare_image(session, &desc), cleanup);
    /* Write the full image as one contiguous chunk starting at offset 0. */
    TEST_ASSERT_EQ_GOTO(
        FWUAL_OK, fwual_write(session, CT_FW_IMAGE_ID, 0U, k_fw_image, CT_FW_IMAGE_SIZE), cleanup);
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_finalize_image(session, CT_FW_IMAGE_ID), cleanup);

    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_close_session(session), cleanup);
    session = NULL;

cleanup:
    if (session != NULL) {
        (void)fwual_close_session(session);
    }
    return result;
}

/**
 * @brief OTA_CT_FW_1.2: multi-chunk sequential write followed by finalize.
 *
 * Split the image into four contiguous chunks (three equal plus a remainder)
 * and finalize the assembled image.
 */
static test_result_t test_fw_write_multi_chunk_sequential(void)
{
    fwual_session_t *session = NULL;
    fwual_image_desc_t desc;
    /* Split the image into 3 roughly equal chunks. */
    const size_t chunk = CT_FW_IMAGE_SIZE / 4U;
    test_result_t result = TEST_PASS;

    CT_FW_ENTER();
    fill_desc(&desc);

    TEST_ASSERT_EQ(FWUAL_OK, fwual_open_session(&session));
    TEST_ASSERT_NOT_NULL_GOTO(session, cleanup);
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_prepare_image(session, &desc), cleanup);

    TEST_ASSERT_EQ_GOTO(
        FWUAL_OK, fwual_write(session, CT_FW_IMAGE_ID, 0U * chunk, &k_fw_image[0U * chunk], chunk),
        cleanup);
    TEST_ASSERT_EQ_GOTO(
        FWUAL_OK, fwual_write(session, CT_FW_IMAGE_ID, 1U * chunk, &k_fw_image[1U * chunk], chunk),
        cleanup);
    TEST_ASSERT_EQ_GOTO(
        FWUAL_OK, fwual_write(session, CT_FW_IMAGE_ID, 2U * chunk, &k_fw_image[2U * chunk], chunk),
        cleanup);
    TEST_ASSERT_EQ_GOTO(FWUAL_OK,
                        fwual_write(session, CT_FW_IMAGE_ID, 3U * chunk, &k_fw_image[3U * chunk],
                                    CT_FW_IMAGE_SIZE - 3U * chunk),
                        cleanup);
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_finalize_image(session, CT_FW_IMAGE_ID), cleanup);

    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_close_session(session), cleanup);
    session = NULL;

cleanup:
    if (session != NULL) {
        (void)fwual_close_session(session);
    }
    return result;
}

/**
 * @brief OTA_CT_FW_1.3: an out-of-order write on a sequential backend must be
 *        rejected with FWUAL_ERR_INVALID_STATE.
 *
 * Skips when the backend does not advertise requires_sequential_writes.
 */
static test_result_t test_fw_write_out_of_order_rejected(void)
{
    fwual_session_t *session = NULL;
    fwual_image_desc_t desc;
    fwual_caps_t caps = { 0 };
    fwual_result_t r;
    test_result_t result = TEST_PASS;

    CT_FW_ENTER();
    TEST_ASSERT_EQ(FWUAL_OK, fwual_get_caps(&caps));

    if (!caps.requires_sequential_writes) {
        TEST_SKIP_WITH("backend does not require sequential writes; out-of-order is permitted");
    }

    fill_desc(&desc);

    TEST_ASSERT_EQ(FWUAL_OK, fwual_open_session(&session));
    TEST_ASSERT_NOT_NULL_GOTO(session, cleanup);
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_prepare_image(session, &desc), cleanup);

    TEST_ASSERT_EQ_GOTO(FWUAL_OK,
                        fwual_write(session, CT_FW_IMAGE_ID, 0U, k_fw_image, CT_FW_IMAGE_SIZE / 2U),
                        cleanup);

    r = fwual_write(session, CT_FW_IMAGE_ID, 0U, k_fw_image, CT_FW_IMAGE_SIZE / 2U);
    TEST_ASSERT_EQ_GOTO(FWUAL_ERR_INVALID_STATE, r, cleanup);

    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_close_session(session), cleanup);
    session = NULL;

cleanup:
    if (session != NULL) {
        (void)fwual_close_session(session);
    }
    return result;
}

/**
 * @brief OTA_CT_FW_1.4: finalizing with fewer bytes than declared must be
 *        rejected with FWUAL_ERR_INVALID_STATE, and the image must not be
 *        reported as staged.
 */
static test_result_t test_fw_finalize_incomplete_rejected(void)
{
    fwual_session_t *session = NULL;
    fwual_image_desc_t desc;
    test_result_t result = TEST_PASS;

    CT_FW_ENTER();
    fill_desc(&desc);

    TEST_ASSERT_EQ(FWUAL_OK, fwual_open_session(&session));
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_prepare_image(session, &desc), cleanup);

    TEST_ASSERT_EQ_GOTO(FWUAL_OK,
                        fwual_write(session, CT_FW_IMAGE_ID, 0U, k_fw_image, CT_FW_IMAGE_SIZE / 2U),
                        cleanup);
    TEST_ASSERT_EQ_GOTO(FWUAL_ERR_INVALID_STATE, fwual_finalize_image(session, CT_FW_IMAGE_ID),
                        cleanup);
    TEST_ASSERT_FALSE_GOTO(fwual_is_image_staged(session, CT_FW_IMAGE_ID), cleanup);

    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_close_session(session), cleanup);
    session = NULL;

cleanup:
    if (session != NULL) {
        (void)fwual_close_session(session);
    }
    return result;
}

/**
 * @brief OTA_CT_FW_1.5: writing past the declared image size must be rejected
 *        with FWUAL_ERR_INVALID_PARAM.
 */
static test_result_t test_fw_write_overflow_rejected(void)
{
    fwual_session_t *session = NULL;
    fwual_image_desc_t desc;
    fwual_result_t r;
    test_result_t result = TEST_PASS;

    CT_FW_ENTER();
    fill_desc(&desc);

    TEST_ASSERT_EQ(FWUAL_OK, fwual_open_session(&session));
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_prepare_image(session, &desc), cleanup);

    TEST_ASSERT_EQ_GOTO(FWUAL_OK,
                        fwual_write(session, CT_FW_IMAGE_ID, 0U, k_fw_image, CT_FW_IMAGE_SIZE - 4U),
                        cleanup);
    r = fwual_write(session, CT_FW_IMAGE_ID, CT_FW_IMAGE_SIZE - 4U, k_fw_image, 8U);
    TEST_ASSERT_EQ_GOTO(FWUAL_ERR_INVALID_PARAM, r, cleanup);

    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_close_session(session), cleanup);
    session = NULL;

cleanup:
    if (session != NULL) {
        (void)fwual_close_session(session);
    }
    return result;
}

/* Verify / Commit Tests */

/**
 * @brief OTA_CT_FW_1.6: verify with the correct SHA-256 must succeed and the
 *        image must report as staged.
 */
static test_result_t test_fw_verify_correct_sha256(void)
{
    fwual_caps_t caps = { 0 };
    fwual_session_t *session = NULL;
    fwual_image_desc_t desc;
    test_result_t result = TEST_PASS;

    CT_FW_ENTER();
    TEST_ASSERT_EQ(FWUAL_OK, fwual_get_caps(&caps));
    fill_desc(&desc);

    TEST_ASSERT_EQ(FWUAL_OK, fwual_open_session(&session));
    TEST_ASSERT_NOT_NULL_GOTO(session, cleanup);
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_prepare_image(session, &desc), cleanup);
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, write_full_image(session, &caps), cleanup);
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_finalize_image(session, CT_FW_IMAGE_ID), cleanup);

    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_verify_image(session, CT_FW_IMAGE_ID), cleanup);
    TEST_ASSERT_TRUE_GOTO(fwual_is_image_staged(session, CT_FW_IMAGE_ID), cleanup);

    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_close_session(session), cleanup);
    session = NULL;

cleanup:
    if (session != NULL) {
        (void)fwual_close_session(session);
    }
    return result;
}

/**
 * @brief OTA_CT_FW_1.7: verify with a wrong hash must be rejected with
 *        FWUAL_ERR_CORRUPT, and the image must not report as staged.
 */
static test_result_t test_fw_verify_wrong_hash_rejected(void)
{
    fwual_caps_t caps = { 0 };
    fwual_session_t *session = NULL;
    fwual_image_desc_t desc;
    test_result_t result = TEST_PASS;

    CT_FW_ENTER();
    TEST_ASSERT_EQ(FWUAL_OK, fwual_get_caps(&caps));
    fill_desc(&desc);

    desc.expected_hash = k_zero_sha256;

    TEST_ASSERT_EQ(FWUAL_OK, fwual_open_session(&session));
    TEST_ASSERT_NOT_NULL_GOTO(session, cleanup);
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_prepare_image(session, &desc), cleanup);
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, write_full_image(session, &caps), cleanup);
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_finalize_image(session, CT_FW_IMAGE_ID), cleanup);

    TEST_ASSERT_EQ_GOTO(FWUAL_ERR_CORRUPT, fwual_verify_image(session, CT_FW_IMAGE_ID), cleanup);
    TEST_ASSERT_FALSE_GOTO(fwual_is_image_staged(session, CT_FW_IMAGE_ID), cleanup);

    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_close_session(session), cleanup);
    session = NULL;

cleanup:
    if (session != NULL) {
        (void)fwual_close_session(session);
    }
    return result;
}

/**
 * @brief OTA_CT_FW_1.8: full lifecycle prepare/write/finalize/verify/commit.
 *
 * Stops before activate() since rebooting into the image needs CT_CAP_REBOOT.
 */
static test_result_t test_fw_full_lifecycle_with_nvs(void)
{
    fwual_caps_t caps = { 0 };
    fwual_session_t *session = NULL;
    fwual_image_desc_t desc;
    test_result_t result = TEST_PASS;

    CT_FW_ENTER();
    TEST_ASSERT_EQ(FWUAL_OK, fwual_get_caps(&caps));
    fill_desc(&desc);

    TEST_ASSERT_EQ(FWUAL_OK, fwual_open_session(&session));
    TEST_ASSERT_NOT_NULL_GOTO(session, cleanup);

    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_prepare_image(session, &desc), cleanup);
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, write_full_image(session, &caps), cleanup);
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_finalize_image(session, CT_FW_IMAGE_ID), cleanup);
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_verify_image(session, CT_FW_IMAGE_ID), cleanup);
    TEST_ASSERT_TRUE_GOTO(fwual_is_image_staged(session, CT_FW_IMAGE_ID), cleanup);
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_commit_session(session), cleanup);

    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_close_session(session), cleanup);
    session = NULL;

cleanup:
    if (session != NULL) {
        (void)fwual_close_session(session);
    }
    return result;
}

/**
 * @brief OTA_CT_FW_1.9: cancel_image() must release the slot so it can be
 *        re-prepared within the same session.
 */
static test_result_t test_fw_cancel_image_slot_reusable(void)
{
    fwual_session_t *session = NULL;
    fwual_image_desc_t desc;
    test_result_t result = TEST_PASS;

    CT_FW_ENTER();
    fill_desc(&desc);

    TEST_ASSERT_EQ(FWUAL_OK, fwual_open_session(&session));
    TEST_ASSERT_NOT_NULL_GOTO(session, cleanup);

    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_prepare_image(session, &desc), cleanup);

    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_cancel_image(session, CT_FW_IMAGE_ID), cleanup);

    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_prepare_image(session, &desc), cleanup);

    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_close_session(session), cleanup);
    session = NULL;

cleanup:
    if (session != NULL) {
        (void)fwual_close_session(session);
    }
    return result;
}

/* State-Machine Guard Tests */

/**
 * @brief A corrupt image must fail verify with FWUAL_ERR_CORRUPT and block
 *        the subsequent commit with FWUAL_ERR_INVALID_STATE.
 */
static test_result_t test_fw_verify_corrupt_blocks_commit(void)
{
    fwual_caps_t caps = { 0 };
    fwual_session_t *session = NULL;
    fwual_image_desc_t desc;
    uint8_t corrupt[CT_FW_IMAGE_SIZE];
    uint64_t offset = 0U;
    size_t step;
    test_result_t result = TEST_PASS;

    CT_FW_ENTER();
    TEST_ASSERT_EQ(FWUAL_OK, fwual_get_caps(&caps));
    fill_desc(&desc);

    (void)memcpy(corrupt, k_fw_image, sizeof(corrupt));
    corrupt[0] ^= 0xFFU;

    step = caps.max_write_size;
    if (step == 0U || step > CT_FW_IMAGE_SIZE) {
        step = CT_FW_IMAGE_SIZE;
    }

    TEST_ASSERT_EQ(FWUAL_OK, fwual_open_session(&session));
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_prepare_image(session, &desc), cleanup);

    while (offset < CT_FW_IMAGE_SIZE) {
        size_t len = (size_t)(CT_FW_IMAGE_SIZE - offset);

        if (len > step) {
            len = step;
        }
        TEST_ASSERT_EQ_GOTO(
            FWUAL_OK, fwual_write(session, CT_FW_IMAGE_ID, offset, &corrupt[offset], len), cleanup);
        offset += len;
    }

    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_finalize_image(session, CT_FW_IMAGE_ID), cleanup);
    TEST_ASSERT_EQ_GOTO(FWUAL_ERR_CORRUPT, fwual_verify_image(session, CT_FW_IMAGE_ID), cleanup);
    TEST_ASSERT_FALSE_GOTO(fwual_is_image_staged(session, CT_FW_IMAGE_ID), cleanup);

    TEST_ASSERT_EQ_GOTO(FWUAL_ERR_INVALID_STATE, fwual_commit_session(session), cleanup);

    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_close_session(session), cleanup);
    session = NULL;

cleanup:
    if (session != NULL) {
        (void)fwual_close_session(session);
    }
    return result;
}

/**
 * @brief write() without a prior prepare_image() must be rejected with
 *        FWUAL_ERR_INVALID_STATE.
 */
static test_result_t test_fw_write_before_prepare(void)
{
    fwual_session_t *session = NULL;
    fwual_result_t r;
    test_result_t result = TEST_PASS;

    CT_FW_ENTER();
    TEST_ASSERT_EQ(FWUAL_OK, fwual_open_session(&session));

    r = fwual_write(session, CT_FW_IMAGE_ID, 0U, k_fw_image, CT_FW_IMAGE_SIZE);
    TEST_ASSERT_EQ_GOTO(FWUAL_ERR_INVALID_STATE, r, cleanup);

    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_close_session(session), cleanup);
    session = NULL;

cleanup:
    if (session != NULL) {
        (void)fwual_close_session(session);
    }
    return result;
}

/**
 * @brief commit_session() without a prior verify_image() must be rejected
 *        with FWUAL_ERR_INVALID_STATE.
 */
static test_result_t test_fw_commit_before_verify(void)
{
    fwual_caps_t caps = { 0 };
    fwual_session_t *session = NULL;
    fwual_image_desc_t desc;
    test_result_t result = TEST_PASS;

    CT_FW_ENTER();
    TEST_ASSERT_EQ(FWUAL_OK, fwual_get_caps(&caps));
    fill_desc(&desc);

    TEST_ASSERT_EQ(FWUAL_OK, fwual_open_session(&session));
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_prepare_image(session, &desc), cleanup);
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, write_full_image(session, &caps), cleanup);
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_finalize_image(session, CT_FW_IMAGE_ID), cleanup);

    TEST_ASSERT_EQ_GOTO(FWUAL_ERR_INVALID_STATE, fwual_commit_session(session), cleanup);

    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_close_session(session), cleanup);
    session = NULL;

cleanup:
    if (session != NULL) {
        (void)fwual_close_session(session);
    }
    return result;
}

/**
 * @brief Closing a session mid-write must discard the staged data so that a
 *        fresh session can prepare the same image again without conflict.
 */
static test_result_t test_fw_close_discards_staged(void)
{
    fwual_session_t *session = NULL;
    fwual_image_desc_t desc;
    test_result_t result = TEST_PASS;

    CT_FW_ENTER();
    fill_desc(&desc);

    TEST_ASSERT_EQ(FWUAL_OK, fwual_open_session(&session));
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_prepare_image(session, &desc), cleanup);
    TEST_ASSERT_EQ_GOTO(FWUAL_OK,
                        fwual_write(session, CT_FW_IMAGE_ID, 0U, k_fw_image, CT_FW_IMAGE_SIZE / 2U),
                        cleanup);

    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_close_session(session), cleanup);
    session = NULL;

    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_open_session(&session), cleanup);
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_prepare_image(session, &desc), cleanup);
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_close_session(session), cleanup);
    session = NULL;

cleanup:
    if (session != NULL) {
        (void)fwual_close_session(session);
    }
    return result;
}

/* Test Registration */

TEST_SUITE_BEGIN(fwual_public)
TEST_REGISTER("-", test_fw_init_and_caps)
TEST_REGISTER("-", test_fw_param_validation)
TEST_REGISTER("-", test_fw_single_session_busy)
TEST_REGISTER("OTA_CT_FW_1.1", test_fw_write_single_chunk_finalize)
TEST_REGISTER("OTA_CT_FW_1.2", test_fw_write_multi_chunk_sequential)
TEST_REGISTER("OTA_CT_FW_1.3", test_fw_write_out_of_order_rejected)
TEST_REGISTER("OTA_CT_FW_1.4", test_fw_finalize_incomplete_rejected)
TEST_REGISTER("OTA_CT_FW_1.5", test_fw_write_overflow_rejected)
TEST_REGISTER("OTA_CT_FW_1.6", test_fw_verify_correct_sha256)
TEST_REGISTER("OTA_CT_FW_1.7", test_fw_verify_wrong_hash_rejected)
TEST_REGISTER("OTA_CT_FW_1.8", test_fw_full_lifecycle_with_nvs)
TEST_REGISTER("OTA_CT_FW_1.9", test_fw_cancel_image_slot_reusable)
TEST_REGISTER("-", test_fw_verify_corrupt_blocks_commit)
TEST_REGISTER("-", test_fw_write_before_prepare)
TEST_REGISTER("-", test_fw_commit_before_verify)
TEST_REGISTER("-", test_fw_close_discards_staged)
TEST_SUITE_END(fwual_public)

/** @} */
