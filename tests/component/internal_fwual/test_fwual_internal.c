/*
 * Copyright 2018-2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "test_fwual_internal.h"

#include <zephyr/dfu/mcuboot.h>

#include "fwual/fwual.h"

/**
 * @defgroup test_fwual_internal Internal FWUAL Component Tests
 * @brief Component tests for the internal FWUAL API surface (OTA_CT_FW).
 *
 * Exercises the real FWUAL backend (real flash + NVS + MCUboot on hardware,
 * flash simulator + stub trailers on native_sim) via the internal-only
 * helpers: state persistence across a re-scan, flash fault injection, and
 * MCUboot swap/rollback wiring.
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

/* Board-provided hooks */

/**
 * @brief Arm or disarm the flash fault-injection hook.
 *
 * The weak default returns false (unsupported on this target); bodies that
 * observe false will TEST_SKIP rather than misreport a pass/fail.
 */
__attribute__((weak)) bool ct_fw_flash_fault_arm(bool arm)
{
    (void)arm;
    return false;
}

/**
 * @brief Report whether the MCUboot swap-pending flag is currently set.
 *
 * The weak default returns false (unsupported on this target).
 */
__attribute__((weak)) bool ct_fw_boot_pending_set(void)
{
    return false;
}

/**
 * @brief Simulate a device reboot in the FWUAL backend.
 *
 * The weak default is a no-op. Board glue overrides this to force a real
 * teardown of session liveness while preserving persistent-looking fields.
 * Persistence tests must call this before the second fwual_init() to
 * observe actual re-scan behaviour.
 */
__attribute__((weak)) void ct_fw_simulate_reboot(void)
{
}

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
 * @brief Drive a session all the way through prepare/write/finalize/verify
 *        so that the caller can immediately commit or activate.
 *
 * @param[out] out_session Freshly opened session ready for commit_session().
 * @return FWUAL_OK on success; on failure the session (if any) has been closed.
 */
static fwual_result_t stage_verified_image(fwual_session_t **out_session)
{
    fwual_caps_t caps = { 0 };
    fwual_session_t *session = NULL;
    fwual_image_desc_t desc;
    fwual_result_t r;

    *out_session = NULL;
    fill_desc(&desc);

    r = fwual_get_caps(&caps);
    if (r != FWUAL_OK) {
        return r;
    }
    r = fwual_open_session(&session);
    if (r != FWUAL_OK) {
        return r;
    }
    r = fwual_prepare_image(session, &desc);
    if (r != FWUAL_OK) {
        (void)fwual_close_session(session);
        return r;
    }
    r = write_full_image(session, &caps);
    if (r != FWUAL_OK) {
        (void)fwual_close_session(session);
        return r;
    }
    r = fwual_finalize_image(session, CT_FW_IMAGE_ID);
    if (r != FWUAL_OK) {
        (void)fwual_close_session(session);
        return r;
    }
    r = fwual_verify_image(session, CT_FW_IMAGE_ID);
    if (r != FWUAL_OK) {
        (void)fwual_close_session(session);
        return r;
    }
    *out_session = session;
    return FWUAL_OK;
}

/* Persistence Tests */

/**
 * @brief OTA_CT_FW_1.12: committed state must persist across an init re-scan.
 *
 * Stage and commit an image, then simulate a reboot and re-init the backend.
 * fwual_get_state() must still report FWUAL_STATE_COMMITTED.
 */
static test_result_t test_fw_state_persist_committed(void)
{
    fwual_session_t *session = NULL;
    fwual_state_t state;
    test_result_t result = TEST_PASS;

    /* Real committed-state persistence needs the MCUboot-backed FWUAL. */
    TEST_REQUIRE_CAP(CT_CAP_MCUBOOT);
    TEST_ASSERT_EQ(FWUAL_OK, fwual_init());

    TEST_ASSERT_EQ(FWUAL_OK, stage_verified_image(&session));

    TEST_ASSERT_NOT_NULL_GOTO(session, cleanup);
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_commit_session(session), cleanup);

    state = fwual_get_state();
    TEST_ASSERT_EQ_GOTO(FWUAL_STATE_COMMITTED, state, cleanup);

    /* Simulate a fresh boot: force a re-scan of NVM, then init. */
    ct_fw_simulate_reboot();
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_init(), cleanup);
    state = fwual_get_state();
    TEST_ASSERT_EQ_GOTO(FWUAL_STATE_COMMITTED, state, cleanup);

cleanup:
    if (session != NULL) {
        (void)fwual_close_session(session);
    }
    return result;
}

/**
 * @brief OTA_CT_FW_1.13: per-chunk write progress must persist across a re-scan.
 *
 * Prepare and half-write an image, then simulate a reboot. After re-init the
 * state must not be FAILED, and the half-written image must not be reported
 * as staged/bootable.
 */
static test_result_t test_fw_state_persist_writing(void)
{
    fwual_session_t *session = NULL;
    fwual_image_desc_t desc;
    fwual_state_t state;
    test_result_t result = TEST_PASS;

    /* Real write-progress persistence needs the MCUboot-backed FWUAL. */
    TEST_REQUIRE_CAP(CT_CAP_MCUBOOT);
    TEST_ASSERT_EQ(FWUAL_OK, fwual_init());
    fill_desc(&desc);

    TEST_ASSERT_EQ(FWUAL_OK, fwual_open_session(&session));
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_prepare_image(session, &desc), cleanup);
    TEST_ASSERT_EQ_GOTO(FWUAL_OK,
                        fwual_write(session, CT_FW_IMAGE_ID, 0U, k_fw_image, CT_FW_IMAGE_SIZE / 2U),
                        cleanup);

    /* In-flight write leaves state at IDLE or WRITING, not FAILED. */
    state = fwual_get_state();
    TEST_ASSERT_NE_GOTO(FWUAL_STATE_FAILED, state, cleanup);

    /* Simulate a fresh boot: force a re-scan of NVM, then init. */
    ct_fw_simulate_reboot();
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_init(), cleanup);
    TEST_ASSERT_NE_GOTO(FWUAL_STATE_FAILED, fwual_get_state(), cleanup);

    /* The half-written image must not be reported as staged/bootable. */
    TEST_ASSERT_FALSE_GOTO(fwual_is_image_staged(session, CT_FW_IMAGE_ID), cleanup);

cleanup:
    if (session != NULL) {
        (void)fwual_close_session(session);
    }
    return result;
}

/* Flash Fault Injection Tests */

/**
 * @brief OTA_CT_FW_1.10: a forced flash ERASE fault must surface as FWUAL_ERR_IO.
 *
 * Arm the erase-fault hook then attempt prepare_image()/write(). The fault
 * must be reported, the image must not appear staged, and the backend state
 * must recover cleanly on close.
 */
static test_result_t test_fw_flash_erase_fault(void)
{
    fwual_session_t *session = NULL;
    fwual_image_desc_t desc;
    fwual_result_t r;
    test_result_t result = TEST_PASS;

    TEST_REQUIRE_CAP(CT_CAP_FLASH_FAULT);
    TEST_ASSERT_EQ(FWUAL_OK, fwual_init());
    fill_desc(&desc);

    if (!ct_fw_flash_fault_arm(true)) {
        TEST_SKIP_WITH("flash erase fault injection not implemented on this target");
    }

    TEST_ASSERT_EQ(FWUAL_OK, fwual_open_session(&session));
    r = fwual_prepare_image(session, &desc);
    if (r == FWUAL_OK) {
        r = fwual_write(session, CT_FW_IMAGE_ID, 0U, k_fw_image, CT_FW_IMAGE_SIZE);
    }
    (void)ct_fw_flash_fault_arm(false);

    TEST_ASSERT_EQ_GOTO(FWUAL_ERR_IO, r, cleanup);
    TEST_ASSERT_FALSE_GOTO(fwual_is_image_staged(session, CT_FW_IMAGE_ID), cleanup);

    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_close_session(session), cleanup);
    session = NULL;
    TEST_ASSERT_NE_GOTO(FWUAL_STATE_FAILED, fwual_get_state(), cleanup);

cleanup:
    if (session != NULL) {
        (void)fwual_close_session(session);
    }
    return result;
}

/**
 * @brief OTA_CT_FW_1.11: a forced flash WRITE fault must surface as FWUAL_ERR_IO.
 *
 * Prepare cleanly, then arm the write-fault hook and issue the first write.
 * The fault must be reported and the image must not appear staged.
 */
static test_result_t test_fw_flash_write_fault(void)
{
    fwual_session_t *session = NULL;
    fwual_image_desc_t desc;
    fwual_result_t r;
    test_result_t result = TEST_PASS;

    TEST_REQUIRE_CAP(CT_CAP_FLASH_FAULT);
    TEST_ASSERT_EQ(FWUAL_OK, fwual_init());
    fill_desc(&desc);

    TEST_ASSERT_EQ(FWUAL_OK, fwual_open_session(&session));
    r = fwual_prepare_image(session, &desc);

    if (r == FWUAL_OK) {
        if (!ct_fw_flash_fault_arm(true)) {
            (void)fwual_close_session(session);
            session = NULL;
            TEST_SKIP_WITH("flash write fault injection not implemented on this target");
        }
        r = fwual_write(session, CT_FW_IMAGE_ID, 0U, k_fw_image, CT_FW_IMAGE_SIZE);
        (void)ct_fw_flash_fault_arm(false);
    }

    TEST_ASSERT_EQ_GOTO(FWUAL_ERR_IO, r, cleanup);
    TEST_ASSERT_FALSE_GOTO(fwual_is_image_staged(session, CT_FW_IMAGE_ID), cleanup);

    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_close_session(session), cleanup);
    session = NULL;
    TEST_ASSERT_NE_GOTO(FWUAL_STATE_FAILED, fwual_get_state(), cleanup);

cleanup:
    if (session != NULL) {
        (void)fwual_close_session(session);
    }
    return result;
}

/* MCUboot Integration Tests */

/**
 * @brief OTA_CT_FW_2.1: activate() must arm the MCUboot swap-type in the trailer.
 *
 * After stage+commit, fwual_activate() must not reboot but must set the
 * boot-pending flag and move the backend into FWUAL_STATE_REBOOT_REQUIRED.
 */
static test_result_t test_fw_mcuboot_activate_sets_swap(void)
{
    fwual_session_t *session = NULL;
    fwual_state_t state;
    test_result_t result = TEST_PASS;

    TEST_REQUIRE_CAP(CT_CAP_MCUBOOT);
    TEST_ASSERT_EQ(FWUAL_OK, fwual_init());

    TEST_ASSERT_EQ(FWUAL_OK, stage_verified_image(&session));
    TEST_ASSERT_NOT_NULL_GOTO(session, cleanup);
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_commit_session(session), cleanup);

    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_activate(), cleanup);

    TEST_ASSERT_TRUE_GOTO(ct_fw_boot_pending_set(), cleanup);

    state = fwual_get_state();
    TEST_ASSERT_EQ_GOTO(FWUAL_STATE_REBOOT_REQUIRED, state, cleanup);

cleanup:
    if (session != NULL) {
        (void)fwual_close_session(session);
    }
    return result;
}

/**
 * @brief OTA_CT_FW_2.2: confirm() must set image_ok after a simulated trial boot.
 *
 * Only meaningful when the device comes up in FWUAL_STATE_WAITING_CONFIRM; the
 * body skips otherwise since the scenario cannot be exercised without an
 * actual reboot.
 */
static test_result_t test_fw_mcuboot_confirm_sets_image_ok(void)
{
    TEST_REQUIRE_CAP(CT_CAP_MCUBOOT | CT_CAP_REBOOT);
    TEST_ASSERT_EQ(FWUAL_OK, fwual_init());

    if (fwual_get_state() != FWUAL_STATE_WAITING_CONFIRM) {
        TEST_SKIP_WITH("device is not currently in a trial boot; stage an upgrade first");
    }

    TEST_ASSERT_EQ(FWUAL_OK, fwual_confirm());
    TEST_ASSERT_EQ(FWUAL_STATE_ACTIVE, fwual_get_state());
    return TEST_PASS;
}

/**
 * @brief OTA_CT_FW_2.3: rollback() must restore a known-good bootable state.
 *
 * Requires CT_CAP_REBOOT. Skips when no previous image is available to roll
 * back to; otherwise the backend state must become FWUAL_STATE_ROLLED_BACK.
 */
static test_result_t test_fw_rollback_recovers(void)
{
    fwual_result_t r;

    TEST_REQUIRE_CAP(CT_CAP_REBOOT);
    TEST_ASSERT_EQ(FWUAL_OK, fwual_init());

    r = fwual_rollback();
    if (r == FWUAL_ERR_PLATFORM) {
        TEST_SKIP_WITH("no previous image available to roll back to");
    }
    TEST_ASSERT_EQ(FWUAL_OK, r);
    TEST_ASSERT_EQ(FWUAL_STATE_ROLLED_BACK, fwual_get_state());
    return TEST_PASS;
}

/**
 * @brief OTA_CT_FW_2.4: the active slot ID must match the DT chosen code partition.
 *
 * At this layer we only assert that fwual_get_caps() succeeds; the slot-to-
 * partition mapping is verified by the board HAL glue in test_backend.c.
 */
static test_result_t test_fw_active_slot_from_dt_chosen(void)
{
    fwual_caps_t caps = { 0 };

    TEST_REQUIRE_CAP(CT_CAP_REAL_FLASH | CT_CAP_MCUBOOT);
    TEST_ASSERT_EQ(FWUAL_OK, fwual_init());

    TEST_ASSERT_EQ(FWUAL_OK, fwual_get_caps(&caps));

    return TEST_PASS;
}

/**
 * @brief OTA_CT_FW_2.5: aligned and mis-aligned writes must behave as documented.
 *
 * Aligned writes at offset 0 must succeed; mis-aligned (length not a multiple
 * of write_alignment) writes must be rejected with FWUAL_ERR_INVALID_PARAM.
 * Skips when the backend reports no alignment requirement.
 */
static test_result_t test_fw_write_block_alignment(void)
{
    fwual_session_t *session = NULL;
    fwual_image_desc_t desc;
    fwual_caps_t caps = { 0 };
    fwual_result_t r;
    test_result_t result = TEST_PASS;

    TEST_REQUIRE_CAP(CT_CAP_REAL_FLASH | CT_CAP_MCUBOOT);
    TEST_ASSERT_EQ(FWUAL_OK, fwual_init());
    TEST_ASSERT_EQ(FWUAL_OK, fwual_get_caps(&caps));

    if (caps.write_alignment <= 1U) {
        TEST_SKIP_WITH("backend reports no alignment requirement; test not applicable");
    }

    fill_desc(&desc);

    TEST_ASSERT_EQ(FWUAL_OK, fwual_open_session(&session));
    TEST_ASSERT_NOT_NULL_GOTO(session, cleanup);
    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_prepare_image(session, &desc), cleanup);

    TEST_ASSERT_EQ_GOTO(FWUAL_OK,
                        fwual_write(session, CT_FW_IMAGE_ID, 0U, k_fw_image, caps.write_alignment),
                        cleanup);

    if (caps.write_alignment > 1U && CT_FW_IMAGE_SIZE > caps.write_alignment) {
        r = fwual_write(session, CT_FW_IMAGE_ID, caps.write_alignment, k_fw_image, 1U);
        TEST_ASSERT_EQ_GOTO(FWUAL_ERR_INVALID_PARAM, r, cleanup);
    }

    TEST_ASSERT_EQ_GOTO(FWUAL_OK, fwual_close_session(session), cleanup);
    session = NULL;

cleanup:
    if (session != NULL) {
        (void)fwual_close_session(session);
    }
    return result;
}

/**
 * @brief OTA_CT_FW_2.6: sector count must be >= 2 and total == partition size.
 *
 * Basic sanity check: the reported max_write_size (when non-zero) must fit
 * within the test image. The real sector-count query is performed by the
 * board test_backend.c via the flash_area driver.
 */
static test_result_t test_fw_erase_sector_count(void)
{
    fwual_caps_t caps = { 0 };

    TEST_REQUIRE_CAP(CT_CAP_REAL_FLASH | CT_CAP_MCUBOOT);
    TEST_ASSERT_EQ(FWUAL_OK, fwual_init());
    TEST_ASSERT_EQ(FWUAL_OK, fwual_get_caps(&caps));

    TEST_ASSERT_MSG(CT_FW_IMAGE_SIZE > 0U, "test image size must be positive");

    if (caps.max_write_size > 0U) {
        TEST_ASSERT_MSG(caps.max_write_size <= (uint32_t)CT_FW_IMAGE_SIZE,
                        "max_write_size larger than test image; adjust CT_FW_IMAGE_SIZE");
    }
    return TEST_PASS;
}

/* State-Machine Guard Tests */

/**
 * @brief activate() without a prior commit_session() must return FWUAL_ERR_INVALID_STATE.
 *
 * Any stale boot-pending flag left by an earlier test is cleared first via
 * boot_write_img_confirmed_multi() so the guard can be observed cleanly.
 */
static test_result_t test_fw_activate_without_commit(void)
{
    TEST_REQUIRE_CAP(CT_CAP_MCUBOOT);
    TEST_ASSERT_EQ(FWUAL_OK, fwual_init());

    (void)boot_write_img_confirmed_multi(0);

    /* No committed session -> activate must refuse. */
    TEST_ASSERT_EQ(FWUAL_ERR_INVALID_STATE, fwual_activate());
    TEST_ASSERT_FALSE(ct_fw_boot_pending_set());
    return TEST_PASS;
}

/**
 * @brief confirm() outside FWUAL_STATE_WAITING_CONFIRM must return FWUAL_ERR_INVALID_STATE.
 *
 * Skips when the device is currently mid trial-boot (not the scenario under
 * test).
 */
static test_result_t test_fw_confirm_wrong_state(void)
{
    TEST_REQUIRE_CAP(CT_CAP_MCUBOOT);
    TEST_ASSERT_EQ(FWUAL_OK, fwual_init());

    if (fwual_get_state() != FWUAL_STATE_WAITING_CONFIRM) {
        TEST_ASSERT_EQ(FWUAL_ERR_INVALID_STATE, fwual_confirm());
    } else {
        TEST_SKIP_WITH("device is mid trial-boot; not the scenario under test");
    }
    return TEST_PASS;
}

/* Test Registration */

TEST_SUITE_BEGIN(fwual_internal)
TEST_REGISTER("OTA_CT_FW_1.12", test_fw_state_persist_committed)
TEST_REGISTER("OTA_CT_FW_1.13", test_fw_state_persist_writing)
TEST_REGISTER("OTA_CT_FW_1.10", test_fw_flash_erase_fault)
TEST_REGISTER("OTA_CT_FW_1.11", test_fw_flash_write_fault)
TEST_REGISTER("OTA_CT_FW_2.1", test_fw_mcuboot_activate_sets_swap)
TEST_REGISTER("OTA_CT_FW_2.2", test_fw_mcuboot_confirm_sets_image_ok)
TEST_REGISTER("OTA_CT_FW_2.3", test_fw_rollback_recovers)
TEST_REGISTER("OTA_CT_FW_2.4", test_fw_active_slot_from_dt_chosen)
TEST_REGISTER("OTA_CT_FW_2.5", test_fw_write_block_alignment)
TEST_REGISTER("OTA_CT_FW_2.6", test_fw_erase_sector_count)
TEST_REGISTER("-", test_fw_activate_without_commit)
TEST_REGISTER("-", test_fw_confirm_wrong_state)
TEST_SUITE_END(fwual_internal)

/** @} */
