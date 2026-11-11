/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

/*
 * FWUAL boot-sequence tests (OTA_UT_FW_8.x).
 *
 * fwual_init() returns early once it has succeeded, and the library keeps its
 * state in statics. The init error paths can therefore only be exercised
 * BEFORE the first successful fwual_init() of the binary. This suite must run
 * first and its tests must stay in this order: a chain of failing init
 * attempts, then exactly one successful init that starts from a persisted
 * REBOOT_REQUIRED state (simulated reboot), followed by the confirm paths.
 *
 * The suite needs a backend that can inject faults and seed NVS (the Zephyr
 * MCUboot fakes). A fault that cannot be armed is a test failure, not a skip.
 */

#include "test_suites.h"

#include "fwual/fwual.h"
#include "fwual_state.h"
#include "fwual_storage_fault.h"
#include "test_framework.h"

#define BOOT_NVS_KEY_STATE ((uint16_t)FWUAL_NVS_KEY_STATE)
#define BOOT_NVS_KEY_LIFECYCLE ((uint16_t)FWUAL_NVS_KEY_LIFECYCLE)

static bool boot_seed_lifecycle(fwual_state_t state)
{
    return fwual_storage_fault_seed_nvs(BOOT_NVS_KEY_LIFECYCLE, &state, sizeof(state));
}

static bool test_fwual_boot_api_before_init(void *params)
{
    bool test_status = true;
    fwual_caps_t caps = { 0 };
    fwual_session_t *session = NULL;
    fwual_installed_image_t list[1] = { 0 };
    size_t count = 1U;
    fwual_result_t r = FWUAL_ERR_INTERNAL;

    (void)params;

    r = fwual_get_caps(&caps);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_ERR_INVALID_STATE, r, exit);

    r = fwual_open_session(&session);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_ERR_INVALID_STATE, r, exit);

    r = fwual_activate();
    TEST_ASSERT_EQUAL_GOTO(FWUAL_ERR_INVALID_STATE, r, exit);

    r = fwual_confirm();
    TEST_ASSERT_EQUAL_GOTO(FWUAL_ERR_INVALID_STATE, r, exit);

    r = fwual_rollback();
    TEST_ASSERT_EQUAL_GOTO(FWUAL_ERR_INVALID_STATE, r, exit);

    r = fwual_list_installed(list, &count);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_ERR_INVALID_STATE, r, exit);

    TEST_ASSERT_EQUAL_GOTO(FWUAL_STATE_FAILED, fwual_get_state(), exit);
    TEST_PRINT_INFO("API calls before fwual_init() correctly rejected");

exit:
    return test_status;
}

static bool test_fwual_boot_init_nvs_mount_fault(void *params)
{
    bool test_status = true;
    fwual_result_t r = FWUAL_ERR_INTERNAL;

    (void)params;

    fwual_storage_fault_reset();
    TEST_ASSERT_GOTO(fwual_storage_fault_arm(FWUAL_STORAGE_FAULT_NVS_MOUNT), exit);

    r = fwual_init();
    TEST_ASSERT_EQUAL_GOTO(FWUAL_ERR_INTERNAL, r, exit);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_STATE_FAILED, fwual_get_state(), exit);
    TEST_PRINT_INFO("fwual_init() correctly failed on nvs_mount error");

exit:
    fwual_storage_fault_reset();
    return test_status;
}

static bool test_fwual_boot_init_slot_open_fault(void *params)
{
    bool test_status = true;
    fwual_result_t r = FWUAL_ERR_INTERNAL;

    (void)params;

    fwual_storage_fault_reset();
    TEST_ASSERT_GOTO(fwual_storage_fault_arm(FWUAL_STORAGE_FAULT_SLOT_OPEN), exit);

    r = fwual_init();
    TEST_ASSERT_EQUAL_GOTO(FWUAL_ERR_INTERNAL, r, exit);
    TEST_ASSERT_GOTO(!fwual_storage_fault_pending(), exit);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_STATE_FAILED, fwual_get_state(), exit);
    TEST_PRINT_INFO("fwual_init() correctly failed on flash_area_open error");

exit:
    fwual_storage_fault_reset();
    return test_status;
}

static bool test_fwual_boot_init_read_state_fault(void *params)
{
    bool test_status = true;
    fwual_result_t r = FWUAL_ERR_INTERNAL;

    (void)params;

    fwual_storage_fault_reset();
    TEST_ASSERT_GOTO(fwual_storage_fault_arm(FWUAL_STORAGE_FAULT_NVS_READ_STATE), exit);

    /* Slot setup succeeds here, so this also leaves the slots initialised. */
    r = fwual_init();
    TEST_ASSERT_EQUAL_GOTO(FWUAL_ERR_INTERNAL, r, exit);
    TEST_ASSERT_GOTO(!fwual_storage_fault_pending(), exit);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_STATE_FAILED, fwual_get_state(), exit);
    TEST_PRINT_INFO("fwual_init() correctly failed on nvs_read(state) error");

exit:
    fwual_storage_fault_reset();
    return test_status;
}

static bool test_fwual_boot_init_read_lifecycle_fault(void *params)
{
    bool test_status = true;
    fwual_result_t r = FWUAL_ERR_INTERNAL;

    (void)params;

    fwual_storage_fault_reset();
    TEST_ASSERT_GOTO(fwual_storage_fault_arm(FWUAL_STORAGE_FAULT_NVS_READ_LIFECYCLE), exit);

    /* Slots are already initialised by the previous attempt (early-exit path). */
    r = fwual_init();
    TEST_ASSERT_EQUAL_GOTO(FWUAL_ERR_INTERNAL, r, exit);
    TEST_ASSERT_GOTO(!fwual_storage_fault_pending(), exit);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_STATE_FAILED, fwual_get_state(), exit);
    TEST_PRINT_INFO("fwual_init() correctly failed on nvs_read(lifecycle) error");

exit:
    fwual_storage_fault_reset();
    return test_status;
}

static bool test_fwual_boot_init_reboot_persist_fault(void *params)
{
    bool test_status = true;
    fwual_result_t r = FWUAL_ERR_INTERNAL;

    (void)params;

    fwual_storage_fault_reset();
    TEST_ASSERT_GOTO(boot_seed_lifecycle(FWUAL_STATE_REBOOT_REQUIRED), exit);
    TEST_ASSERT_GOTO(fwual_storage_fault_arm(FWUAL_STORAGE_FAULT_NVS_WRITE_LIFECYCLE), exit);

    r = fwual_init();
    TEST_ASSERT_EQUAL_GOTO(FWUAL_ERR_INTERNAL, r, exit);
    TEST_ASSERT_GOTO(!fwual_storage_fault_pending(), exit);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_STATE_FAILED, fwual_get_state(), exit);
    TEST_PRINT_INFO("fwual_init() correctly failed persisting WAITING_CONFIRM");

exit:
    fwual_storage_fault_reset();
    return test_status;
}

static bool test_fwual_boot_init_after_reboot(void *params)
{
    bool test_status = true;
    fwual_update_state_t update_state = FWUAL_UPDATE_STATE_IDLE;
    fwual_result_t r = FWUAL_ERR_INTERNAL;

    (void)params;

    fwual_storage_fault_reset();
    TEST_ASSERT_GOTO(boot_seed_lifecycle(FWUAL_STATE_REBOOT_REQUIRED), exit);
    /* Seed the session state key as well so init sees a fully populated NVS. There is
     * no public accessor for the restored session state, so it is not asserted. */
    TEST_ASSERT_GOTO(fwual_storage_fault_seed_nvs(BOOT_NVS_KEY_STATE, &update_state,
                                                  sizeof(update_state)),
                     exit);

    r = fwual_init();
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_STATE_WAITING_CONFIRM, fwual_get_state(), exit);
    TEST_PRINT_INFO("fwual_init() after simulated reboot reached WAITING_CONFIRM");

exit:
    return test_status;
}

static bool test_fwual_boot_confirm_bootutil_fault(void *params)
{
    bool test_status = true;
    fwual_result_t r = FWUAL_ERR_INTERNAL;

    (void)params;

    TEST_ASSERT_EQUAL_GOTO(FWUAL_STATE_WAITING_CONFIRM, fwual_get_state(), exit);
    TEST_ASSERT_GOTO(fwual_storage_fault_arm(FWUAL_STORAGE_FAULT_BOOT_CONFIRM), exit);

    r = fwual_confirm();
    TEST_ASSERT_EQUAL_GOTO(FWUAL_ERR_PLATFORM, r, exit);
    TEST_ASSERT_GOTO(!fwual_storage_fault_pending(), exit);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_STATE_WAITING_CONFIRM, fwual_get_state(), exit);
    TEST_PRINT_INFO("fwual_confirm() correctly reported the bootutil failure");

exit:
    return test_status;
}

static bool test_fwual_boot_confirm_success(void *params)
{
    bool test_status = true;
    fwual_result_t r = FWUAL_ERR_INTERNAL;

    (void)params;

    TEST_ASSERT_EQUAL_GOTO(FWUAL_STATE_WAITING_CONFIRM, fwual_get_state(), exit);

    r = fwual_confirm();
    TEST_ASSERT_EQUAL_GOTO(FWUAL_OK, r, exit);
    TEST_ASSERT_EQUAL_GOTO(FWUAL_STATE_ACTIVE, fwual_get_state(), exit);
    TEST_PRINT_INFO("fwual_confirm() moved the lifecycle to ACTIVE");

exit:
    return test_status;
}

void register_fwual_boot_tests(void)
{
    TEST_REGISTER_ID("OTA_UT_FW_8.1", test_fwual_boot_api_before_init);
    TEST_REGISTER_ID("OTA_UT_FW_8.2", test_fwual_boot_init_nvs_mount_fault);
    TEST_REGISTER_ID("OTA_UT_FW_8.3", test_fwual_boot_init_slot_open_fault);
    TEST_REGISTER_ID("OTA_UT_FW_8.4", test_fwual_boot_init_read_state_fault);
    TEST_REGISTER_ID("OTA_UT_FW_8.5", test_fwual_boot_init_read_lifecycle_fault);
    TEST_REGISTER_ID("OTA_UT_FW_8.6", test_fwual_boot_init_reboot_persist_fault);
    TEST_REGISTER_ID("OTA_UT_FW_8.7", test_fwual_boot_init_after_reboot);
    TEST_REGISTER_ID("OTA_UT_FW_8.8", test_fwual_boot_confirm_bootutil_fault);
    TEST_REGISTER_ID("OTA_UT_FW_8.9", test_fwual_boot_confirm_success);
}
