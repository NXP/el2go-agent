/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef EL2GO_FWUAL_STORAGE_FAULT_H
#define EL2GO_FWUAL_STORAGE_FAULT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * @enum fwual_storage_fault_t
 * @brief Identifies a class of underlying storage operation to fault-inject.
 *
 * These are expressed in terms of *what FWUAL is doing*, not which driver
 * or API is underneath, so the enum is stable across backends.
 */
typedef enum {
    FWUAL_STORAGE_FAULT_NONE = 0,      /**< No fault (sentinel, never armed). */
    FWUAL_STORAGE_FAULT_STAGE_ERASE,   /**< Erasing the staging area (fwual_prepare_image). */
    FWUAL_STORAGE_FAULT_STAGE_WRITE,   /**< Writing image bytes (fwual_write). */
    FWUAL_STORAGE_FAULT_STATE_PERSIST, /**< Next NVS write of ANY key. Prefer NVS_WRITE_*. */
    FWUAL_STORAGE_FAULT_BANK_ERASE,    /**< Erasing the boot bank (fwual_rollback). */

    FWUAL_STORAGE_FAULT_SLOT_OPEN, /**< Opening the staging flash area. */
    FWUAL_STORAGE_FAULT_SLOT_READ, /**< Reading back the staging area (fwual_verify_image). */
    FWUAL_STORAGE_FAULT_NVS_MOUNT, /**< Mounting the NVS store (fwual_init). Sticky until reset. */
    FWUAL_STORAGE_FAULT_NVS_READ_STATE,     /**< Reading the persisted session state key. */
    FWUAL_STORAGE_FAULT_NVS_READ_LIFECYCLE, /**< Reading the persisted lifecycle state key. */
    /* Per-key write faults (NVS_WRITE_*) hit exactly one key and are the preferred way to
     * target a specific persist; STATE_PERSIST above fails whichever write comes first. */
    FWUAL_STORAGE_FAULT_NVS_WRITE_STATE,     /**< Persisting the session state key only. */
    FWUAL_STORAGE_FAULT_NVS_WRITE_PROGRESS,  /**< Persisting the write-progress key only. */
    FWUAL_STORAGE_FAULT_NVS_WRITE_LIFECYCLE, /**< Persisting the lifecycle state key only. */
    FWUAL_STORAGE_FAULT_NVS_WRITE_SHORT,     /**< Next NVS write reports a short length. */
    FWUAL_STORAGE_FAULT_BOOT_REQUEST,        /**< boot_request_upgrade_multi (fwual_activate). */
    FWUAL_STORAGE_FAULT_BOOT_CONFIRM,        /**< boot_write_img_confirmed_multi (fwual_confirm). */
    FWUAL_STORAGE_FAULT_BOOT_HEADER,         /**< boot_read_bank_header (fwual_list_installed). */
} fwual_storage_fault_t;

/**
 * @brief Reset all injected faults and any fake storage state to a clean,
 *        unfaulted starting point.
 *
 * Must be safe to call even if no fault is currently armed.
 */
void fwual_storage_fault_reset(void);

/**
 * @brief Query whether this platform's fault-injection backend can inject
 *        the given fault kind.
 *
 * Suites that only build for Zephyr (boot and error suites) treat an
 * unsupported fault as a test FAILURE, so a missing backend cannot silently
 * hide coverage. Only suites that also build for other backends may check
 * this and skip.
 *
 * @param fault Fault kind to query.
 * @return true if @p fault can be armed on this platform, false otherwise.
 */
bool fwual_storage_fault_supported(fwual_storage_fault_t fault);

/**
 * @brief Arm the next occurrence of @p fault to fail.
 *
 * The fault is expected to be consumed (disarmed) automatically the first
 * time the corresponding underlying operation executes.
 *
 * @param fault Fault kind to arm.
 * @return true if the fault was armed, false if unsupported on this
 *         platform (see fwual_storage_fault_supported()).
 */
bool fwual_storage_fault_arm(fwual_storage_fault_t fault);

/**
 * @brief Override the write-block alignment reported by the fake storage.
 *
 * @param align Alignment in bytes.
 * @return true if applied, false if unsupported on this platform.
 */
bool fwual_storage_fault_set_write_align(uint32_t align);

/**
 * @brief Query whether a boot upgrade request is currently pending in the
 *        fake bootloader state.
 *
 * @return true if a boot upgrade is pending, false otherwise (including
 *         when unsupported on this platform).
 */
bool fwual_storage_fault_boot_upgrade_pending(void);

/**
 * @brief Pre-load a persisted NVS value, as if written by a previous boot.
 *
 * @param key  NVS key id (see fwual_nvs_key_t in fwual_state.h).
 * @param data Value bytes.
 * @param len  Number of bytes.
 * @return true if stored, false if unsupported on this platform or out of range.
 */
bool fwual_storage_fault_seed_nvs(uint16_t key, const void *data, size_t len);

/**
 * @brief Query whether an armed one-shot fault was left unconsumed.
 *
 * Tests call this after the operation under test to prove that the injected
 * fault was really hit. The sticky NVS mount fault is not reported here.
 *
 * @return true if an armed fault is still pending, false otherwise (including
 *         when unsupported on this platform).
 */
bool fwual_storage_fault_pending(void);

/** @} */ /* end of fwual_storage_fault */

#endif /* EL2GO_FWUAL_STORAGE_FAULT_H */
