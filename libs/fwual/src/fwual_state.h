/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __FWUAL_STATE_H__
#define __FWUAL_STATE_H__

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "fwual/fwual.h"

#ifdef CONFIG_FWUAL_MCUBOOT_IMAGE_COUNT
#define FWUAL_MAX_IMAGES CONFIG_FWUAL_MCUBOOT_IMAGE_COUNT
#else
#define FWUAL_MAX_IMAGES 4U /* fallback for non-Zephyr builds */
#endif

/**
 * @brief Persisted update state -- persisted on every transition.
 *
 * This is the FWUAL-internal session lifecycle state, distinct from the
 * public fwual_state_t which covers the full device update lifecycle.
 */
typedef enum fwual_update_state_t {
    FWUAL_UPDATE_STATE_IDLE,           /**< No active session. */
    FWUAL_UPDATE_STATE_SESSION_OPEN,   /**< Session open, no images prepared. */
    FWUAL_UPDATE_STATE_IMAGE_PREPARED, /**< One or more images prepared. */
} fwual_update_state_t;

/**
 * @brief NVS key identifiers for FWUAL persistent storage.
 *
 * These values are part of the on-flash NVS layout and MUST NOT be changed
 * once deployed -- doing so would corrupt persisted state on existing devices.
 */
typedef enum {
    FWUAL_NVS_KEY_STATE,          /**< fwual_update_state_t -- session lifecycle state */
    FWUAL_NVS_KEY_WRITE_PROGRESS, /**< fwual_write_progress_t -- per-image write progress */
} fwual_nvs_key_t;

/**
 * @brief Minimal write-progress record persisted to NVS after each chunk.
 *
 * Intentionally small -- avoids writing the full session struct (which
 * contains image descriptors with pointers) on every fwual_write() call.
 */
typedef struct {
    fwual_image_id_t image_id;     /**< Image this record belongs to. */
    uint64_t bytes_written;        /**< Total bytes written so far. */
    uint64_t next_expected_offset; /**< Next expected write offset. */
    bool finalized;                /**< True after fwual_finalize_image(). */
    bool verified;                 /**< True after fwual_verify_image(). */
} fwual_write_progress_t;

/**
 * @brief Per-image slot context, held inside the session.
 */
typedef struct fwual_image_slot_t {
    fwual_image_id_t image_id;     /**< Image identifier provided by the caller. */
    fwual_image_desc_t desc;       /**< Image descriptor (size, type, etc.). */
    bool prepared;                 /**< True if the slot has been successfully prepared. */
    bool cancelled;                /**< True if the slot has been cancelled. */
    bool finalized;                /**< True if fwual_finalize_image() succeeded for this slot. */
    bool verified;                 /**< True if fwual_verify_image() succeeded for this slot. */
    uint32_t slot_index;           /**< Backend-assigned slot index. */
    uint64_t bytes_written;        /**< Total bytes written so far. */
    uint64_t next_expected_offset; /**< Next expected write offset (sequential enforcement). */
} fwual_image_slot_t;

/**
 * @brief Session context -- valid only while session.active == true.
 *
 * The struct tag is 'fwual_session' to satisfy the forward declaration
 * in fwual_types.h: typedef struct fwual_session fwual_session_t;
 */
struct fwual_session {
    bool active;                                 /**< True if a session is currently open. */
    fwual_image_slot_t images[FWUAL_MAX_IMAGES]; /**< Per-image slot contexts. */
    size_t image_count;                          /**< Number of images prepared in this session. */
};

/**
 * @brief Top-level internal state -- single static instance.
 */
typedef struct fwual_internal_state_t {
    bool initialized;                  /**< True if fwual_init() has been called successfully. */
    struct fwual_session session;      /**< Active session context. */
    fwual_update_state_t update_state; /**< Persisted across resets. */
    fwual_caps_t caps;                 /**< Cached capabilities - populated once at fwual_init(). */
} fwual_internal_state_t;

#endif /* __FWUAL_STATE_H__ */
