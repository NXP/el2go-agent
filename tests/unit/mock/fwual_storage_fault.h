/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef EL2GO_FWUAL_STORAGE_FAULT_H
#define EL2GO_FWUAL_STORAGE_FAULT_H

#include <stdbool.h>
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
    FWUAL_STORAGE_FAULT_STATE_PERSIST, /**< Persisting session/progress metadata. */
    FWUAL_STORAGE_FAULT_BANK_ERASE,    /**< Erasing the boot bank (fwual_rollback). */
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
 * Tests must check this before calling fwual_storage_fault_arm() and SKIP
 * (return true without exercising the fault) when unsupported, rather than
 * fail.
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

/** @} */ /* end of fwual_storage_fault */

#endif /* EL2GO_FWUAL_STORAGE_FAULT_H */
