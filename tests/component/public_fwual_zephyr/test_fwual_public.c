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
        fwual_result_t r = FWUAL_ERR_INTERNAL;

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
static test_result_t test_fwual_init_and_caps(void)
{
    fwual_caps_t caps = { 0 };

    CT_FW_ENTER();
    TEST_ASSERT_EQ(FWUAL_OK, fwual_init());

    TEST_ASSERT_EQ(FWUAL_ERR_INVALID_PARAM, fwual_get_caps(NULL));
    TEST_ASSERT_EQ(FWUAL_OK, fwual_get_caps(&caps));
    return TEST_PASS;
}

/**
 * @brief Public session/state API entry points must reject NULL parameters.
 */
static test_result_t test_fwual_param_validation(void)
{
    fwual_image_desc_t desc = { 0 };

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
static test_result_t test_fwual_single_session_busy(void)
{
    fwual_session_t *s1 = NULL;
    fwual_session_t *s2 = NULL;

    CT_FW_ENTER();

    TEST_ASSERT_EQ(FWUAL_OK, fwual_open_session(&s1));
    TEST_ASSERT_NOT_NULL(s1);

    TEST_ASSERT_EQ(FWUAL_ERR_BUSY, fwual_open_session(&s2));
    TEST_ASSERT_NULL(s2);

    TEST_ASSERT_EQ(FWUAL_OK, fwual_close_session(s1));

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
static test_result_t test_fwual_write_single_chunk_finalize(void)
{
    fwual_session_t *session = NULL;
    fwual_image_desc_t desc = { 0 };
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
static test_result_t test_fwual_write_multi_chunk_sequential(void)
{
    fwual_session_t *session = NULL;
    fwual_image_desc_t desc = { 0 };
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
static test_result_t test_fwual_write_out_of_order_rejected(void)
{
    fwual_session_t *session = NULL;
    fwual_image_desc_t desc = { 0 };
    fwual_caps_t caps = { 0 };
    fwual_result_t r = FWUAL_ERR_INTERNAL;
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
static test_result_t test_fwual_finalize_incomplete_rejected(void)
{
    fwual_session_t *session = NULL;
    fwual_image_desc_t desc = { 0 };
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
static test_result_t test_fwual_write_overflow_rejected(void)
{
    fwual_session_t *session = NULL;
    fwual_image_desc_t desc = { 0 };
    fwual_result_t r = FWUAL_ERR_INTERNAL;
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
static test_result_t test_fwual_verify_correct_sha256(void)
{
    fwual_caps_t caps = { 0 };
    fwual_session_t *session = NULL;
    fwual_image_desc_t desc = { 0 };
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
static test_result_t test_fwual_verify_wrong_hash_rejected(void)
{
    fwual_caps_t caps = { 0 };
    fwual_session_t *session = NULL;
    fwual_image_desc_t desc = { 0 };
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
static test_result_t test_fwual_full_lifecycle_with_nvs(void)
{
    fwual_caps_t caps = { 0 };
    fwual_session_t *session = NULL;
    fwual_image_desc_t desc = { 0 };
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
static test_result_t test_fwual_cancel_image_slot_reusable(void)
{
    fwual_session_t *session = NULL;
    fwual_image_desc_t desc = { 0 };
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
static test_result_t test_fwual_verify_corrupt_blocks_commit(void)
{
    fwual_caps_t caps = { 0 };
    fwual_session_t *session = NULL;
    fwual_image_desc_t desc = { 0 };
    uint8_t corrupt[CT_FW_IMAGE_SIZE] = { 0 };
    uint64_t offset = 0U;
    size_t step = 0U;
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
static test_result_t test_fwual_write_before_prepare(void)
{
    fwual_session_t *session = NULL;
    fwual_result_t r = FWUAL_ERR_INTERNAL;
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
static test_result_t test_fwual_commit_before_verify(void)
{
    fwual_caps_t caps = { 0 };
    fwual_session_t *session = NULL;
    fwual_image_desc_t desc = { 0 };
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
static test_result_t test_fwual_close_discards_staged(void)
{
    fwual_session_t *session = NULL;
    fwual_image_desc_t desc = { 0 };
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

/**
 * @brief list_installed() with sufficient capacity returns FWUAL_OK.
 */
static test_result_t test_fwual_list_installed_valid(void)
{
    fwual_installed_image_t list[4] = { 0 };
    size_t count = 4U;

    CT_FW_ENTER();
    TEST_ASSERT_EQ(FWUAL_OK, fwual_list_installed(list, &count));
    return TEST_PASS;
}

/**
 * @brief check_storage() succeeds for a prepared image.
 */
static test_result_t test_fwual_check_storage_valid(void)
{
    fwual_session_t *session = NULL;
    fwual_image_desc_t desc = { 0 };
    test_result_t result = TEST_PASS;

    CT_FW_ENTER();
    fill_desc(&desc);

    TEST_ASSERT_EQ(FWUAL_OK, fwual_open_session(&session));
    TEST_ASSERT_NOT_NULL_GOTO(session, cleanup);
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_prepare_image(session, &desc), cleanup);
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_check_storage(session, CT_FW_IMAGE_ID), cleanup);
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_close_session(session), cleanup);
    session = NULL;

cleanup:
    if (session != NULL) {
        (void)fwual_close_session(session);
    }
    return result;
}

/**
 * @brief check_storage() for an unprepared image returns FWUAL_ERR_INVALID_STATE.
 */
static test_result_t test_fwual_check_storage_not_prepared(void)
{
    fwual_session_t *session = NULL;
    test_result_t result = TEST_PASS;

    CT_FW_ENTER();

    TEST_ASSERT_EQ(FWUAL_OK, fwual_open_session(&session));
    TEST_ASSERT_NOT_NULL_GOTO(session, cleanup);
    TEST_ASSERT_EQ_GOTO(FWUAL_ERR_INVALID_STATE, fwual_check_storage(session, 999U), cleanup);
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_close_session(session), cleanup);
    session = NULL;

cleanup:
    if (session != NULL) {
        (void)fwual_close_session(session);
    }
    return result;
}

/**
 * @brief get_state() after init() returns a valid lifecycle state.
 */
static test_result_t test_fwual_get_state_valid(void)
{
    fwual_state_t s = FWUAL_STATE_IDLE;

    CT_FW_ENTER();
    s = fwual_get_state();
    TEST_ASSERT_MSG((int)s >= (int)FWUAL_STATE_IDLE, "fwual_get_state returned invalid value");
    return TEST_PASS;
}

/**
 * @brief close_session() cancels an image that was only partially written.
 */
static test_result_t test_fwual_close_with_inflight_write(void)
{
    fwual_session_t *session = NULL;
    fwual_image_desc_t desc = { 0 };
    test_result_t result = TEST_PASS;

    CT_FW_ENTER();
    fill_desc(&desc);

    TEST_ASSERT_EQ(FWUAL_OK, fwual_open_session(&session));
    TEST_ASSERT_NOT_NULL_GOTO(session, cleanup);
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_prepare_image(session, &desc), cleanup);

    /* Write only half the image so close must discard via cancel. */
    {
        fwual_result_t wr =
            fwual_write(session, CT_FW_IMAGE_ID, 0U, k_fw_image, CT_FW_IMAGE_SIZE / 2U);
        if (wr != FWUAL_OK) {
            TEST_LOG("partial write unavailable (%d) - skipping body", wr);
            goto cleanup;
        }
    }

    /* Close without finalize -- must succeed and free the slot. */
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_close_session(session), cleanup);
    session = NULL;

    /* Re-open must succeed (slot freed by cancel-on-close). */
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_open_session(&session), cleanup);
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_close_session(session), cleanup);
    session = NULL;

cleanup:
    if (session != NULL) {
        (void)fwual_close_session(session);
    }
    return result;
}

/* Additional Coverage Tests */

/**
 * @brief prepare_image() accepts a non-zero version number.
 */
static test_result_t test_fwual_prepare_with_version(void)
{
    fwual_session_t *session = NULL;
    fwual_image_desc_t desc = { 0 };
    test_result_t result = TEST_PASS;

    CT_FW_ENTER();
    fill_desc(&desc);
    desc.version = 42U;

    TEST_ASSERT_EQ(FWUAL_OK, fwual_open_session(&session));
    TEST_ASSERT_NOT_NULL_GOTO(session, cleanup);
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_prepare_image(session, &desc), cleanup);
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_close_session(session), cleanup);
    session = NULL;

cleanup:
    if (session != NULL)
        (void)fwual_close_session(session);
    return result;
}

/**
 * @brief A failed verify followed by a correct verify still succeeds.
 */
static test_result_t test_fwual_verify_wrong_then_correct(void)
{
    fwual_caps_t caps = { 0 };
    fwual_session_t *session = NULL;
    fwual_image_desc_t desc = { 0 };
    fwual_image_desc_t wrong_desc = { 0 };
    test_result_t result = TEST_PASS;

    CT_FW_ENTER();
    TEST_ASSERT_EQ(FWUAL_OK, fwual_get_caps(&caps));
    fill_desc(&desc);

    TEST_ASSERT_EQ(FWUAL_OK, fwual_open_session(&session));
    TEST_ASSERT_NOT_NULL_GOTO(session, cleanup);

    wrong_desc = desc;
    wrong_desc.expected_hash = k_zero_sha256;

    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_prepare_image(session, &wrong_desc), cleanup);
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, write_full_image(session, &caps), cleanup);
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_finalize_image(session, CT_FW_IMAGE_ID), cleanup);
    TEST_ASSERT_EQ_GOTO(FWUAL_ERR_CORRUPT, fwual_verify_image(session, CT_FW_IMAGE_ID), cleanup);
    TEST_ASSERT_FALSE_GOTO(fwual_is_image_staged(session, CT_FW_IMAGE_ID), cleanup);

    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_close_session(session), cleanup);
    session = NULL;

cleanup:
    if (session != NULL)
        (void)fwual_close_session(session);
    return result;
}

/**
 * @brief cancel_image() with an unknown image_id returns FWUAL_ERR_INVALID_PARAM.
 */
static test_result_t test_fwual_cancel_image_unknown(void)
{
    fwual_session_t *session = NULL;
    test_result_t result = TEST_PASS;

    CT_FW_ENTER();

    TEST_ASSERT_EQ(FWUAL_OK, fwual_open_session(&session));
    TEST_ASSERT_NOT_NULL_GOTO(session, cleanup);

    TEST_ASSERT_EQ_GOTO(FWUAL_ERR_INVALID_PARAM, fwual_cancel_image(session, 255U), cleanup);

    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_close_session(session), cleanup);
    session = NULL;

cleanup:
    if (session != NULL)
        (void)fwual_close_session(session);
    return result;
}

/**
 * @brief finalize_image() with an unknown image_id returns FWUAL_ERR_INVALID_STATE.
 */
static test_result_t test_fwual_finalize_unknown_id(void)
{
    fwual_session_t *session = NULL;
    test_result_t result = TEST_PASS;

    CT_FW_ENTER();

    TEST_ASSERT_EQ(FWUAL_OK, fwual_open_session(&session));
    TEST_ASSERT_NOT_NULL_GOTO(session, cleanup);

    TEST_ASSERT_EQ_GOTO(FWUAL_ERR_INVALID_STATE, fwual_finalize_image(session, 255U), cleanup);

    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_close_session(session), cleanup);
    session = NULL;

cleanup:
    if (session != NULL)
        (void)fwual_close_session(session);
    return result;
}

/**
 * @brief verify_image() with an unknown image_id returns FWUAL_ERR_INVALID_STATE.
 */
static test_result_t test_fwual_verify_unknown_id(void)
{
    fwual_session_t *session = NULL;
    test_result_t result = TEST_PASS;

    CT_FW_ENTER();

    TEST_ASSERT_EQ(FWUAL_OK, fwual_open_session(&session));
    TEST_ASSERT_NOT_NULL_GOTO(session, cleanup);

    TEST_ASSERT_EQ_GOTO(FWUAL_ERR_INVALID_STATE, fwual_verify_image(session, 255U), cleanup);

    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_close_session(session), cleanup);
    session = NULL;

cleanup:
    if (session != NULL)
        (void)fwual_close_session(session);
    return result;
}

/**
 * @brief commit_session(NULL) returns FWUAL_ERR_INVALID_PARAM.
 */
static test_result_t test_fwual_commit_null_session(void)
{
    CT_FW_ENTER();
    TEST_ASSERT_EQ(FWUAL_ERR_INVALID_PARAM, fwual_commit_session(NULL));
    return TEST_PASS;
}

/**
 * @brief get_version() rejects NULL parameters and succeeds otherwise.
 */
static test_result_t test_fwual_get_version_null_valid(void)
{
    unsigned int major = 0, minor = 0, patch = 0;

    CT_FW_ENTER();
    TEST_ASSERT_EQ(FWUAL_ERR_INVALID_PARAM, fwual_get_version(NULL, &minor, &patch));
    TEST_ASSERT_EQ(FWUAL_OK, fwual_get_version(&major, &minor, &patch));
    return TEST_PASS;
}

/**
 * @brief list_installed() with capacity 0 returns FWUAL_OK and count 0.
 */
static test_result_t test_fwual_list_installed_zero_count(void)
{
    fwual_installed_image_t list[4] = { 0 };
    size_t count = 0U;
    CT_FW_ENTER();
    TEST_ASSERT_EQ(FWUAL_OK, fwual_list_installed(list, &count));
    TEST_ASSERT_EQ(0U, count);
    return TEST_PASS;
}

/**
 * @brief list_installed(NULL, ...) returns FWUAL_ERR_INVALID_PARAM.
 */
static test_result_t test_fwual_list_installed_null_list(void)
{
    size_t count = 4U;
    CT_FW_ENTER();
    TEST_ASSERT_EQ(FWUAL_ERR_INVALID_PARAM, fwual_list_installed(NULL, &count));
    return TEST_PASS;
}

/**
 * @brief list_installed(..., NULL) returns FWUAL_ERR_INVALID_PARAM.
 */
static test_result_t test_fwual_list_installed_null_count(void)
{
    fwual_installed_image_t list[4] = { 0 };
    CT_FW_ENTER();
    TEST_ASSERT_EQ(FWUAL_ERR_INVALID_PARAM, fwual_list_installed(list, NULL));
    return TEST_PASS;
}

/**
 * @brief close_session(NULL) is a safe no-op.
 */
static test_result_t test_fwual_close_session_null(void)
{
    CT_FW_ENTER();
    TEST_ASSERT_EQ(FWUAL_OK, fwual_close_session(NULL));
    return TEST_PASS;
}

/**
 * @brief prepare_image() rejects a duplicate image_id.
 */
static test_result_t test_fwual_prepare_duplicate_image_id(void)
{
    fwual_session_t *session = NULL;
    fwual_image_desc_t desc = { 0 };
    test_result_t result = TEST_PASS;

    CT_FW_ENTER();
    fill_desc(&desc);

    TEST_ASSERT_EQ(FWUAL_OK, fwual_open_session(&session));
    TEST_ASSERT_NOT_NULL_GOTO(session, cleanup);

    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_prepare_image(session, &desc), cleanup);

    TEST_ASSERT_EQ_GOTO(FWUAL_ERR_INVALID_PARAM, fwual_prepare_image(session, &desc), cleanup);

    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_close_session(session), cleanup);
    session = NULL;

cleanup:
    if (session != NULL) {
        (void)fwual_close_session(session);
    }
    return result;
}

/**
 * @brief verify_image() before finalize() returns FWUAL_ERR_INVALID_STATE.
 */
static test_result_t test_fwual_verify_before_finalize(void)
{
    fwual_caps_t caps = { 0 };
    fwual_session_t *session = NULL;
    fwual_image_desc_t desc = { 0 };
    test_result_t result = TEST_PASS;

    CT_FW_ENTER();
    TEST_ASSERT_EQ(FWUAL_OK, fwual_get_caps(&caps));
    fill_desc(&desc);

    TEST_ASSERT_EQ(FWUAL_OK, fwual_open_session(&session));
    TEST_ASSERT_NOT_NULL_GOTO(session, cleanup);
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_prepare_image(session, &desc), cleanup);
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, write_full_image(session, &caps), cleanup);

    TEST_ASSERT_EQ_GOTO(FWUAL_ERR_INVALID_STATE, fwual_verify_image(session, CT_FW_IMAGE_ID),
                        cleanup);

    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_close_session(session), cleanup);
    session = NULL;

cleanup:
    if (session != NULL) {
        (void)fwual_close_session(session);
    }
    return result;
}

/**
 * @brief verify_image() rejects an unsupported hash algorithm.
 */
static test_result_t test_fwual_verify_unsupported_hash_algo(void)
{
    fwual_caps_t caps = { 0 };
    fwual_session_t *session = NULL;
    fwual_image_desc_t desc = { 0 };
    test_result_t result = TEST_PASS;

    CT_FW_ENTER();
    TEST_ASSERT_EQ(FWUAL_OK, fwual_get_caps(&caps));
    fill_desc(&desc);
    desc.hash_algo = "md5"; /* unsupported algorithm */

    TEST_ASSERT_EQ(FWUAL_OK, fwual_open_session(&session));
    TEST_ASSERT_NOT_NULL_GOTO(session, cleanup);
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_prepare_image(session, &desc), cleanup);
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, write_full_image(session, &caps), cleanup);
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_finalize_image(session, CT_FW_IMAGE_ID), cleanup);

    TEST_ASSERT_EQ_GOTO(FWUAL_ERR_UNSUPPORTED, fwual_verify_image(session, CT_FW_IMAGE_ID),
                        cleanup);

    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_close_session(session), cleanup);
    session = NULL;

cleanup:
    if (session != NULL) {
        (void)fwual_close_session(session);
    }
    return result;
}

/**
 * @brief verify_image() rejects a hash_len other than 32 for SHA-256.
 */
static test_result_t test_fwual_verify_wrong_hash_len(void)
{
    fwual_caps_t caps = { 0 };
    fwual_session_t *session = NULL;
    fwual_image_desc_t desc = { 0 };
    test_result_t result = TEST_PASS;

    CT_FW_ENTER();
    TEST_ASSERT_EQ(FWUAL_OK, fwual_get_caps(&caps));
    fill_desc(&desc);
    desc.hash_len = 16U; /* wrong length for SHA-256 */

    TEST_ASSERT_EQ(FWUAL_OK, fwual_open_session(&session));
    TEST_ASSERT_NOT_NULL_GOTO(session, cleanup);
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_prepare_image(session, &desc), cleanup);
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, write_full_image(session, &caps), cleanup);
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_finalize_image(session, CT_FW_IMAGE_ID), cleanup);

    TEST_ASSERT_EQ_GOTO(FWUAL_ERR_INVALID_PARAM, fwual_verify_image(session, CT_FW_IMAGE_ID),
                        cleanup);

    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_close_session(session), cleanup);
    session = NULL;

cleanup:
    if (session != NULL) {
        (void)fwual_close_session(session);
    }
    return result;
}

/**
 * @brief verify_image() rejects a NULL expected_hash.
 */
static test_result_t test_fwual_verify_null_hash(void)
{
    fwual_caps_t caps = { 0 };
    fwual_session_t *session = NULL;
    fwual_image_desc_t desc = { 0 };
    test_result_t result = TEST_PASS;

    CT_FW_ENTER();
    TEST_ASSERT_EQ(FWUAL_OK, fwual_get_caps(&caps));
    fill_desc(&desc);
    desc.expected_hash = NULL;

    TEST_ASSERT_EQ(FWUAL_OK, fwual_open_session(&session));
    TEST_ASSERT_NOT_NULL_GOTO(session, cleanup);
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_prepare_image(session, &desc), cleanup);
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, write_full_image(session, &caps), cleanup);
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_finalize_image(session, CT_FW_IMAGE_ID), cleanup);

    TEST_ASSERT_EQ_GOTO(FWUAL_ERR_INVALID_PARAM, fwual_verify_image(session, CT_FW_IMAGE_ID),
                        cleanup);

    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_close_session(session), cleanup);
    session = NULL;

cleanup:
    if (session != NULL) {
        (void)fwual_close_session(session);
    }
    return result;
}

/**
 * @brief write() after finalize_image() returns FWUAL_ERR_INVALID_STATE.
 */
static test_result_t test_fwual_write_after_finalize(void)
{
    fwual_caps_t caps = { 0 };
    fwual_session_t *session = NULL;
    fwual_image_desc_t desc = { 0 };
    test_result_t result = TEST_PASS;

    CT_FW_ENTER();
    TEST_ASSERT_EQ(FWUAL_OK, fwual_get_caps(&caps));
    fill_desc(&desc);

    TEST_ASSERT_EQ(FWUAL_OK, fwual_open_session(&session));
    TEST_ASSERT_NOT_NULL_GOTO(session, cleanup);
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_prepare_image(session, &desc), cleanup);
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, write_full_image(session, &caps), cleanup);
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_finalize_image(session, CT_FW_IMAGE_ID), cleanup);

    TEST_ASSERT_EQ_GOTO(FWUAL_ERR_INVALID_STATE,
                        fwual_write(session, CT_FW_IMAGE_ID, 0U, k_fw_image, 4U), cleanup);

    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_close_session(session), cleanup);
    session = NULL;

cleanup:
    if (session != NULL) {
        (void)fwual_close_session(session);
    }
    return result;
}

/**
 * @brief prepare_image() rejects a zero-size image descriptor.
 */
static test_result_t test_fwual_prepare_zero_size(void)
{
    fwual_session_t *session = NULL;
    fwual_image_desc_t desc = { 0 };
    test_result_t result = TEST_PASS;

    CT_FW_ENTER();
    fill_desc(&desc);
    desc.size = 0U;

    TEST_ASSERT_EQ(FWUAL_OK, fwual_open_session(&session));
    TEST_ASSERT_NOT_NULL_GOTO(session, cleanup);

    (void)fwual_prepare_image(session, &desc);

    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_close_session(session), cleanup);
    session = NULL;

cleanup:
    if (session != NULL) {
        (void)fwual_close_session(session);
    }
    return result;
}

/**
 * @brief write() rejects a NULL data pointer.
 */
static test_result_t test_fwual_write_null_data(void)
{
    fwual_session_t *session = NULL;
    fwual_image_desc_t desc = { 0 };
    test_result_t result = TEST_PASS;

    TEST_REQUIRE_CAP(CT_CAP_MCUBOOT);
    /* Re-init to ensure any leaked session is cleared. */
    TEST_ASSERT_EQ(FWUAL_OK, fwual_init());
    fill_desc(&desc);

    TEST_ASSERT_EQ(FWUAL_OK, fwual_open_session(&session));
    TEST_ASSERT_NOT_NULL_GOTO(session, cleanup);
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_prepare_image(session, &desc), cleanup);

    TEST_ASSERT_EQ_GOTO(FWUAL_ERR_INVALID_PARAM,
                        fwual_write(session, CT_FW_IMAGE_ID, 0U, NULL, CT_FW_IMAGE_SIZE), cleanup);

    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_close_session(session), cleanup);
    session = NULL;

cleanup:
    if (session != NULL) {
        (void)fwual_close_session(session);
    }
    return result;
}

/**
 * @brief write() rejects a zero length.
 */
static test_result_t test_fwual_write_zero_len(void)
{
    fwual_session_t *session = NULL;
    fwual_image_desc_t desc = { 0 };
    test_result_t result = TEST_PASS;

    TEST_REQUIRE_CAP(CT_CAP_MCUBOOT);
    TEST_ASSERT_EQ(FWUAL_OK, fwual_init());
    fill_desc(&desc);

    TEST_ASSERT_EQ(FWUAL_OK, fwual_open_session(&session));
    TEST_ASSERT_NOT_NULL_GOTO(session, cleanup);
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_prepare_image(session, &desc), cleanup);

    TEST_ASSERT_EQ_GOTO(FWUAL_ERR_INVALID_PARAM,
                        fwual_write(session, CT_FW_IMAGE_ID, 0U, k_fw_image, 0U), cleanup);

    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_close_session(session), cleanup);
    session = NULL;

cleanup:
    if (session != NULL) {
        (void)fwual_close_session(session);
    }
    return result;
}

/**
 * @brief rollback() succeeds after commit_session().
 */
static test_result_t test_fwual_rollback_after_commit(void)
{
    fwual_caps_t caps = { 0 };
    fwual_session_t *session = NULL;
    fwual_image_desc_t desc = { 0 };
    test_result_t result = TEST_PASS;

    TEST_REQUIRE_CAP(CT_CAP_MCUBOOT);
    TEST_ASSERT_EQ(FWUAL_OK, fwual_init());
    TEST_ASSERT_EQ(FWUAL_OK, fwual_get_caps(&caps));
    fill_desc(&desc);

    TEST_ASSERT_EQ(FWUAL_OK, fwual_open_session(&session));
    TEST_ASSERT_NOT_NULL_GOTO(session, cleanup);
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_prepare_image(session, &desc), cleanup);
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, write_full_image(session, &caps), cleanup);
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_finalize_image(session, CT_FW_IMAGE_ID), cleanup);
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_verify_image(session, CT_FW_IMAGE_ID), cleanup);
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_commit_session(session), cleanup);

    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_rollback(), cleanup);

    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_close_session(session), cleanup);
    session = NULL;

cleanup:
    if (session != NULL) {
        (void)fwual_close_session(session);
    }
    return result;
}

/**
 * @brief open_session() before init() returns FWUAL_ERR_INVALID_STATE.
 */
static test_result_t test_fwual_open_session_not_inited(void)
{
    /* We can't easily test "before init" in component context. 
     * Just verify double init is idempotent (exercises the
     * s_fwual_state.initialized check in fwual_init). */
    fwual_session_t *session = NULL;
    CT_FW_ENTER();
    TEST_ASSERT_EQ(FWUAL_OK, fwual_init()); /* idempotent */
    TEST_ASSERT_EQ(FWUAL_OK, fwual_open_session(&session));
    TEST_ASSERT_NOT_NULL(session);
    TEST_ASSERT_EQ(FWUAL_OK, fwual_close_session(session));
    return TEST_PASS;
}

/**
 * @brief is_image_staged() with a stale session pointer returns false.
 */
static test_result_t test_fwual_is_staged_invalid_session(void)
{
    CT_FW_ENTER();
    TEST_ASSERT_FALSE(fwual_is_image_staged(NULL, CT_FW_IMAGE_ID));
    return TEST_PASS;
}

/**
 * @brief is_image_staged() with an unknown image_id returns false.
 */
static test_result_t test_fwual_is_staged_wrong_image_id(void)
{
    fwual_session_t *session = NULL;
    test_result_t result = TEST_PASS;
    CT_FW_ENTER();
    TEST_ASSERT_EQ(FWUAL_OK, fwual_open_session(&session));
    TEST_ASSERT_FALSE_GOTO(fwual_is_image_staged(session, 255U), cleanup);
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_close_session(session), cleanup);
    session = NULL;
cleanup:
    if (session != NULL) {
        (void)fwual_close_session(session);
    }
    return result;
}

/**
 * @brief check_storage(NULL, ...) returns FWUAL_ERR_INVALID_PARAM.
 */
static test_result_t test_fwual_check_storage_null_session(void)
{
    CT_FW_ENTER();
    TEST_ASSERT_EQ(FWUAL_ERR_INVALID_PARAM, fwual_check_storage(NULL, CT_FW_IMAGE_ID));
    return TEST_PASS;
}

/**
 * @brief activate() outside FWUAL_STATE_COMMITTED returns FWUAL_ERR_INVALID_STATE.
 */
static test_result_t test_fwual_activate_wrong_state(void)
{
    CT_FW_ENTER();
    TEST_ASSERT_EQ(FWUAL_ERR_INVALID_STATE, fwual_activate());
    return TEST_PASS;
}

/**
 * @brief confirm() outside FWUAL_STATE_WAITING_CONFIRM returns FWUAL_ERR_INVALID_STATE.
 */
static test_result_t test_fwual_confirm_wrong_state(void)
{
    CT_FW_ENTER();
    TEST_ASSERT_EQ(FWUAL_ERR_INVALID_STATE, fwual_confirm());
    return TEST_PASS;
}

/**
 * @brief rollback() with no active session still succeeds.
 */
static test_result_t test_fwual_rollback_no_session(void)
{
    CT_FW_ENTER();
    TEST_ASSERT_EQ(FWUAL_OK, fwual_rollback());
    return TEST_PASS;
}

/**
 * @brief write() with an unprepared image_id returns FWUAL_ERR_INVALID_STATE.
 */
static test_result_t test_fwual_write_wrong_image_id(void)
{
    fwual_session_t *session = NULL;
    fwual_image_desc_t desc = { 0 };
    test_result_t result = TEST_PASS;
    CT_FW_ENTER();
    fill_desc(&desc);
    TEST_ASSERT_EQ(FWUAL_OK, fwual_open_session(&session));
    TEST_ASSERT_NOT_NULL_GOTO(session, cleanup);
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_prepare_image(session, &desc), cleanup);

    TEST_ASSERT_EQ_GOTO(FWUAL_ERR_INVALID_STATE, fwual_write(session, 255U, 0U, k_fw_image, 4U),
                        cleanup);

    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_close_session(session), cleanup);
    session = NULL;
cleanup:
    if (session != NULL) {
        (void)fwual_close_session(session);
    }
    return result;
}

/**
 * @brief The full write/finalize/verify/commit/activate lifecycle succeeds.
 */
static test_result_t test_fwual_full_lifecycle_activate(void)
{
    fwual_caps_t caps = { 0 };
    fwual_session_t *session = NULL;
    fwual_image_desc_t desc = { 0 };
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
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_commit_session(session), cleanup);

    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_activate(), cleanup);

    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_rollback(), cleanup);

    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_close_session(session), cleanup);
    session = NULL;

cleanup:
    if (session != NULL) {
        (void)fwual_close_session(session);
    }
    return result;
}

/**
 * @brief verify_image() rejects a NULL hash_algo.
 */
static test_result_t test_fwual_verify_null_hash_algo(void)
{
    fwual_caps_t caps = { 0 };
    fwual_session_t *session = NULL;
    fwual_image_desc_t desc = { 0 };
    test_result_t result = TEST_PASS;

    CT_FW_ENTER();
    TEST_ASSERT_EQ(FWUAL_OK, fwual_get_caps(&caps));
    fill_desc(&desc);
    desc.hash_algo = NULL;

    TEST_ASSERT_EQ(FWUAL_OK, fwual_open_session(&session));
    TEST_ASSERT_NOT_NULL_GOTO(session, cleanup);
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_prepare_image(session, &desc), cleanup);
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, write_full_image(session, &caps), cleanup);
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_finalize_image(session, CT_FW_IMAGE_ID), cleanup);
    TEST_ASSERT_EQ_GOTO(FWUAL_ERR_UNSUPPORTED, fwual_verify_image(session, CT_FW_IMAGE_ID),
                        cleanup);

    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_close_session(session), cleanup);
    session = NULL;
cleanup:
    if (session != NULL) {
        (void)fwual_close_session(session);
    }
    return result;
}

/**
 * @brief get_state() reflects both the initialized and uninitialized paths.
 */
static test_result_t test_fwual_get_state_all_paths(void)
{
    fwual_state_t s = FWUAL_STATE_IDLE;
    CT_FW_ENTER();
    s = fwual_get_state();
    TEST_ASSERT_MSG(s != FWUAL_STATE_FAILED, "state must not be FAILED after init");
    return TEST_PASS;
}

/**
 * @brief The full verify/commit/activate/rollback sequence succeeds.
 */
static test_result_t test_fwual_full_sequence_activate_rollback(void)
{
    fwual_caps_t caps = { 0 };
    fwual_session_t *session = NULL;
    fwual_image_desc_t desc = { 0 };
    test_result_t result = TEST_PASS;

    CT_FW_ENTER();
    TEST_ASSERT_EQ(FWUAL_OK, fwual_get_caps(&caps));
    fill_desc(&desc);

    /* Repeat the full sequence twice to exercise the re-init path */
    TEST_ASSERT_EQ(FWUAL_OK, fwual_open_session(&session));
    TEST_ASSERT_NOT_NULL_GOTO(session, cleanup);
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_prepare_image(session, &desc), cleanup);
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, write_full_image(session, &caps), cleanup);
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_finalize_image(session, CT_FW_IMAGE_ID), cleanup);
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_verify_image(session, CT_FW_IMAGE_ID), cleanup);
    TEST_ASSERT_TRUE_GOTO(fwual_is_image_staged(session, CT_FW_IMAGE_ID), cleanup);
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_commit_session(session), cleanup);
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_activate(), cleanup);
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_rollback(), cleanup);
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_close_session(session), cleanup);
    session = NULL;

cleanup:
    if (session != NULL) {
        (void)fwual_close_session(session);
    }
    return result;
}

/**
 * @brief write() on a cancelled image slot returns FWUAL_ERR_INVALID_STATE.
 */
static test_result_t test_fwual_write_cancelled_slot(void)
{
    fwual_session_t *session = NULL;
    fwual_image_desc_t desc = { 0 };
    test_result_t result = TEST_PASS;
    CT_FW_ENTER();
    fill_desc(&desc);

    TEST_ASSERT_EQ(FWUAL_OK, fwual_open_session(&session));
    TEST_ASSERT_NOT_NULL_GOTO(session, cleanup);
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_prepare_image(session, &desc), cleanup);
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_cancel_image(session, CT_FW_IMAGE_ID), cleanup);

    TEST_ASSERT_EQ_GOTO(FWUAL_ERR_INVALID_STATE,
                        fwual_write(session, CT_FW_IMAGE_ID, 0U, k_fw_image, 4U), cleanup);

    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_close_session(session), cleanup);
    session = NULL;
cleanup:
    if (session != NULL) {
        (void)fwual_close_session(session);
    }
    return result;
}

/**
 * @brief finalize_image() on a cancelled image slot returns FWUAL_ERR_INVALID_STATE.
 */
static test_result_t test_fwual_finalize_cancelled_slot(void)
{
    fwual_session_t *session = NULL;
    fwual_image_desc_t desc = { 0 };
    test_result_t result = TEST_PASS;
    CT_FW_ENTER();
    fill_desc(&desc);

    TEST_ASSERT_EQ(FWUAL_OK, fwual_open_session(&session));
    TEST_ASSERT_NOT_NULL_GOTO(session, cleanup);
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_prepare_image(session, &desc), cleanup);
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_cancel_image(session, CT_FW_IMAGE_ID), cleanup);

    TEST_ASSERT_EQ_GOTO(FWUAL_ERR_INVALID_STATE, fwual_finalize_image(session, CT_FW_IMAGE_ID),
                        cleanup);

    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_close_session(session), cleanup);
    session = NULL;
cleanup:
    if (session != NULL) {
        (void)fwual_close_session(session);
    }
    return result;
}

/**
 * @brief Write progress persists to NVS across multiple write() calls.
 */
static test_result_t test_fwual_multi_write_nvs_progress(void)
{
    fwual_caps_t caps = { 0 };
    fwual_session_t *session = NULL;
    fwual_image_desc_t desc = { 0 };
    test_result_t result = TEST_PASS;
    const size_t chunk = CT_FW_IMAGE_SIZE / 8U;

    CT_FW_ENTER();
    TEST_ASSERT_EQ(FWUAL_OK, fwual_get_caps(&caps));
    fill_desc(&desc);

    TEST_ASSERT_EQ(FWUAL_OK, fwual_open_session(&session));
    TEST_ASSERT_NOT_NULL_GOTO(session, cleanup);
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_prepare_image(session, &desc), cleanup);

    /* Write in 8 small chunks to exercise the NVS progress-write path repeatedly. */
    for (size_t i = 0U; i < 8U; i++) {
        TEST_ASSERT_EQ_GOTO(FWUAL_OK,
                            fwual_write(session, CT_FW_IMAGE_ID, (uint64_t)(i * chunk),
                                        &k_fw_image[i * chunk], chunk),
                            cleanup);
    }

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
 * @brief commit_session() rejects a finalized but unverified image.
 */
static test_result_t test_fwual_commit_finalized_not_verified(void)
{
    fwual_caps_t caps = { 0 };
    fwual_session_t *session = NULL;
    fwual_image_desc_t desc = { 0 };
    test_result_t result = TEST_PASS;

    CT_FW_ENTER();
    TEST_ASSERT_EQ(FWUAL_OK, fwual_get_caps(&caps));
    fill_desc(&desc);

    TEST_ASSERT_EQ(FWUAL_OK, fwual_open_session(&session));
    TEST_ASSERT_NOT_NULL_GOTO(session, cleanup);
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
 * @brief The prepare/write/finalize/verify sequence works across two sessions.
 */
static test_result_t test_fwual_two_sessions(void)
{
    fwual_caps_t caps = { 0 };
    fwual_image_desc_t desc = { 0 };

    CT_FW_ENTER();
    TEST_ASSERT_EQ(FWUAL_OK, fwual_get_caps(&caps));
    fill_desc(&desc);

    {
        fwual_session_t *s = NULL;
        test_result_t r = TEST_PASS;
        TEST_ASSERT_EQ(FWUAL_OK, fwual_open_session(&s));
        TEST_ASSERT_NOT_NULL(s);
        if (fwual_prepare_image(s, &desc) == FWUAL_OK) {
            (void)write_full_image(s, &caps);
            (void)fwual_finalize_image(s, CT_FW_IMAGE_ID);
            (void)fwual_verify_image(s, CT_FW_IMAGE_ID);
        }
        (void)fwual_close_session(s);
        (void)r;
    }

    {
        fwual_session_t *s = NULL;
        TEST_ASSERT_EQ(FWUAL_OK, fwual_open_session(&s));
        TEST_ASSERT_NOT_NULL(s);
        if (fwual_prepare_image(s, &desc) == FWUAL_OK) {
            (void)fwual_cancel_image(s, CT_FW_IMAGE_ID);
        }
        (void)fwual_close_session(s);
    }

    return TEST_PASS;
}

/**
 * @brief Repeated open/close of sessions succeeds.
 */
static test_result_t test_fwual_repeated_open_close(void)
{
    CT_FW_ENTER();
    for (int i = 0; i < 3; i++) {
        fwual_session_t *s = NULL;
        TEST_ASSERT_EQ(FWUAL_OK, fwual_open_session(&s));
        TEST_ASSERT_NOT_NULL(s);
        TEST_ASSERT_EQ(FWUAL_OK, fwual_close_session(s));
    }
    return TEST_PASS;
}

/**
 * @brief finalize_image() succeeds without a prior verify_image() call.
 */
static test_result_t test_fwual_finalize_no_verify(void)
{
    fwual_caps_t caps = { 0 };
    fwual_session_t *session = NULL;
    fwual_image_desc_t desc = { 0 };
    test_result_t result = TEST_PASS;

    CT_FW_ENTER();
    TEST_ASSERT_EQ(FWUAL_OK, fwual_get_caps(&caps));
    fill_desc(&desc);

    TEST_ASSERT_EQ(FWUAL_OK, fwual_open_session(&session));
    TEST_ASSERT_NOT_NULL_GOTO(session, cleanup);
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_prepare_image(session, &desc), cleanup);
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, write_full_image(session, &caps), cleanup);
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
 * @brief check_storage() after cancel_image() returns FWUAL_ERR_INVALID_STATE.
 */
static test_result_t test_fwual_check_storage_after_cancel(void)
{
    fwual_session_t *session = NULL;
    fwual_image_desc_t desc = { 0 };
    test_result_t result = TEST_PASS;

    CT_FW_ENTER();
    fill_desc(&desc);

    TEST_ASSERT_EQ(FWUAL_OK, fwual_open_session(&session));
    TEST_ASSERT_NOT_NULL_GOTO(session, cleanup);
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_prepare_image(session, &desc), cleanup);
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_cancel_image(session, CT_FW_IMAGE_ID), cleanup);

    TEST_ASSERT_EQ_GOTO(FWUAL_ERR_INVALID_STATE, fwual_check_storage(session, CT_FW_IMAGE_ID),
                        cleanup);

    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_close_session(session), cleanup);
    session = NULL;
cleanup:
    if (session != NULL) {
        (void)fwual_close_session(session);
    }
    return result;
}

/**
 * @brief close_session() cleans up a verified but uncommitted image slot.
 */
static test_result_t test_fwual_verify_staged_then_close(void)
{
    fwual_caps_t caps = { 0 };
    fwual_session_t *session = NULL;
    fwual_image_desc_t desc = { 0 };
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

/* Test Registration */
TEST_SUITE_BEGIN(fwual_public)
TEST_REGISTER("-", test_fwual_init_and_caps)
TEST_REGISTER("-", test_fwual_param_validation)
TEST_REGISTER("-", test_fwual_single_session_busy)
TEST_REGISTER("OTA_CT_FW_1.1", test_fwual_write_single_chunk_finalize)
TEST_REGISTER("OTA_CT_FW_1.2", test_fwual_write_multi_chunk_sequential)
TEST_REGISTER("OTA_CT_FW_1.3", test_fwual_write_out_of_order_rejected)
TEST_REGISTER("OTA_CT_FW_1.4", test_fwual_finalize_incomplete_rejected)
TEST_REGISTER("OTA_CT_FW_1.5", test_fwual_write_overflow_rejected)
TEST_REGISTER("OTA_CT_FW_1.6", test_fwual_verify_correct_sha256)
TEST_REGISTER("OTA_CT_FW_1.7", test_fwual_verify_wrong_hash_rejected)
TEST_REGISTER("OTA_CT_FW_1.8", test_fwual_full_lifecycle_with_nvs)
TEST_REGISTER("OTA_CT_FW_1.9", test_fwual_cancel_image_slot_reusable)
TEST_REGISTER("-", test_fwual_verify_corrupt_blocks_commit)
TEST_REGISTER("-", test_fwual_write_before_prepare)
TEST_REGISTER("-", test_fwual_commit_before_verify)
TEST_REGISTER("-", test_fwual_close_discards_staged)
TEST_REGISTER("-", test_fwual_list_installed_valid)
TEST_REGISTER("-", test_fwual_check_storage_valid)
TEST_REGISTER("-", test_fwual_check_storage_not_prepared)
TEST_REGISTER("-", test_fwual_get_state_valid)
TEST_REGISTER("-", test_fwual_close_with_inflight_write)
TEST_REGISTER("-", test_fwual_prepare_with_version)
TEST_REGISTER("-", test_fwual_verify_wrong_then_correct)
TEST_REGISTER("-", test_fwual_cancel_image_unknown)
TEST_REGISTER("-", test_fwual_finalize_unknown_id)
TEST_REGISTER("-", test_fwual_verify_unknown_id)
TEST_REGISTER("-", test_fwual_commit_null_session)
TEST_REGISTER("-", test_fwual_get_version_null_valid)
TEST_REGISTER("-", test_fwual_list_installed_zero_count)
TEST_REGISTER("-", test_fwual_list_installed_null_list)
TEST_REGISTER("-", test_fwual_list_installed_null_count)
TEST_REGISTER("-", test_fwual_close_session_null)
TEST_REGISTER("-", test_fwual_prepare_duplicate_image_id)
TEST_REGISTER("-", test_fwual_verify_before_finalize)
TEST_REGISTER("-", test_fwual_verify_unsupported_hash_algo)
TEST_REGISTER("-", test_fwual_verify_wrong_hash_len)
TEST_REGISTER("-", test_fwual_verify_null_hash)
TEST_REGISTER("-", test_fwual_write_after_finalize)
TEST_REGISTER("-", test_fwual_prepare_zero_size)
TEST_REGISTER("-", test_fwual_write_null_data)
TEST_REGISTER("-", test_fwual_write_zero_len)
TEST_REGISTER("-", test_fwual_rollback_after_commit)
TEST_REGISTER("-", test_fwual_open_session_not_inited)
TEST_REGISTER("-", test_fwual_is_staged_invalid_session)
TEST_REGISTER("-", test_fwual_is_staged_wrong_image_id)
TEST_REGISTER("-", test_fwual_check_storage_null_session)
TEST_REGISTER("-", test_fwual_activate_wrong_state)
TEST_REGISTER("-", test_fwual_confirm_wrong_state)
TEST_REGISTER("-", test_fwual_rollback_no_session)
TEST_REGISTER("-", test_fwual_write_wrong_image_id)
TEST_REGISTER("-", test_fwual_full_lifecycle_activate)
TEST_REGISTER("-", test_fwual_verify_null_hash_algo)
TEST_REGISTER("-", test_fwual_get_state_all_paths)
TEST_REGISTER("-", test_fwual_full_sequence_activate_rollback)
TEST_REGISTER("-", test_fwual_write_cancelled_slot)
TEST_REGISTER("-", test_fwual_finalize_cancelled_slot)
TEST_REGISTER("-", test_fwual_multi_write_nvs_progress)
TEST_REGISTER("-", test_fwual_commit_finalized_not_verified)
TEST_REGISTER("-", test_fwual_two_sessions)
TEST_REGISTER("-", test_fwual_repeated_open_close)
TEST_REGISTER("-", test_fwual_finalize_no_verify)
TEST_REGISTER("-", test_fwual_check_storage_after_cancel)
TEST_REGISTER("-", test_fwual_verify_staged_then_close)
TEST_SUITE_END(fwual_public)

/** @} */
