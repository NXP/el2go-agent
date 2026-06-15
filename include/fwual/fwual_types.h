/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright 2026 NXP
 */

#ifndef __FWUAL_TYPES_H__
#define __FWUAL_TYPES_H__

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * @brief Logical image identifier
 *
 * Assigned by the OTA Agent and used to address a specific firmware image
 * (e.g. application core, radio firmware, secure enclave image).
 */
typedef uint32_t fwual_image_id_t;

/**
 * @brief Opaque update session handle
 *
 * Returned by fwual_open_session() and passed as the first argument to all
 * session-scoped API functions. The caller must treat this as an opaque
 * value and must not dereference or inspect it.
 */
typedef struct fwual_session fwual_session_t;

/**
 * @brief Return code for all FWUAL API functions
 */
typedef enum {
    FWUAL_OK = 0,                               /**< Operation completed successfully */
    FWUAL_ERR_INVALID_PARAM,                    /**< NULL pointer or otherwise invalid argument */
    FWUAL_ERR_INVALID_STATE,                    /**< API called in the wrong lifecycle state */
    FWUAL_ERR_NO_SPACE,                         /**< Insufficient storage capacity for the image */
    FWUAL_ERR_IO,                               /**< Flash or NVM read/write failure */
    FWUAL_ERR_CORRUPT,                          /**< Hash mismatch or damaged data detected */
    FWUAL_ERR_VERIFY,                           /**< Signature or dm-verity verification failure */
    FWUAL_ERR_UNSUPPORTED,                      /**< Capability not available on this backend */
    FWUAL_ERR_BUSY,                             /**< Another session is already active */
    FWUAL_ERR_PLATFORM,                         /**< Platform, OS, or bootloader-level error */
    FWUAL_ERR_INTERNAL,                         /**< Unexpected internal error */
    FWUAL_RESULT_UNINITIALIZED = 0x7FFFFFFF,    /**< Sentinel — for defensive local variable
                                                *   initialization only; must never be
                                                *   returned by any API function */
} fwual_result_t;

/**
 * @brief Device-level firmware update state
 *
 * Persisted in NVM and survives power loss. Read via fwual_get_state() on
 * every boot to detect interrupted sessions or pending confirmations.
 *
 * Lifecycle (happy path):
 *   IDLE -> WRITING -> STAGED -> COMMITTED -> REBOOT_REQUIRED ->
 *   WAITING_CONFIRM -> ACTIVE
 *
 * Failure states: FAILED, ROLLED_BACK
 */
typedef enum {
    FWUAL_STATE_IDLE = 0,           /**< No update in progress */
    FWUAL_STATE_WRITING,            /**< Image data is being written to storage */
    FWUAL_STATE_STAGED,             /**< All images finalized and hash-verified */
    FWUAL_STATE_COMMITTED,          /**< Session committed; images staged for activation */
    FWUAL_STATE_REBOOT_REQUIRED,    /**< Bootloader flags set; reboot needed */
    FWUAL_STATE_WAITING_CONFIRM,    /**< Trial boot in progress; confirm required */
    FWUAL_STATE_ACTIVE,             /**< New firmware confirmed and permanently active */
    FWUAL_STATE_ROLLED_BACK,        /**< Update rolled back to previous known-good image */
    FWUAL_STATE_FAILED,             /**< Update failed; device is in a known-good state */
} fwual_state_t;

/**
 * @brief Type of firmware image to be applied
 */
typedef enum {
    FWUAL_UPDATE_FULL = 0,      /**< Complete image replacement */
    FWUAL_UPDATE_DELTA,         /**< Differential patch; size and hash refer to reconstructed image */
} fwual_update_type_t;

/**
 * @brief Metadata for a single firmware image
 *
 * Provided by the OTA Agent before writing begins. FWUAL uses this descriptor
 * to provision storage, perform integrity verification, and report version
 * information.
 *
 * For FWUAL_UPDATE_DELTA: size and expected_hash describe the final
 * reconstructed image, not the delta stream. FWUAL SHALL NOT derive size or
 * hash from the transport stream.
 */
typedef struct {
    fwual_image_id_t
        image_id;           /**< Logical image identifier assigned by the OTA Agent */
    uint64_t size;          /**< Final reconstructed image size in bytes */
    uint32_t version;       /**< OTA-Agent-defined version number; used for reporting only */
    fwual_update_type_t
        update_type;        /**< FWUAL_UPDATE_FULL or FWUAL_UPDATE_DELTA */
    const char *
        hash_algo;          /**< Null-terminated hash algorithm string (e.g. "sha256") */
    const uint8_t *
        expected_hash;      /**< Expected digest buffer; must remain valid for session lifetime */
    size_t hash_len;        /**< Digest length in bytes (e.g. 32 for SHA-256) */
} fwual_image_desc_t;

/**
 * @brief Information about a currently installed image
 *
 * Returned by fwual_list_installed() to describe the images present on the
 * device at query time.
 */
typedef struct {
    fwual_image_id_t image_id;  /**< Logical image identifier */
    uint32_t version;           /**< Installed version number as reported by the backend */
    bool confirmed;             /**< true if confirmed as successfully running after last activation */
} fwual_installed_image_t;

/**
 * @brief Backend constraints and capabilities
 *
 * Time-invariant per boot. Query once via fwual_get_caps() and cache the
 * result. The OTA Agent uses these values to adapt its write strategy at
 * runtime (e.g. enforce sequential writes, limit chunk size).
 */
typedef struct {
    bool requires_sequential_writes;    /**< If true, fwual_write() offsets must be strictly monotonic */
    bool rejects_overlaps;              /**< If true, overlapping write ranges are rejected */
    bool supports_delta;                /**< If true, FWUAL_UPDATE_DELTA is supported */
    uint32_t write_alignment;           /**< Required byte alignment for offset and len; 1 if none */
    uint32_t max_write_size;            /**< Max bytes per fwual_write() call; 0 if no limit */
} fwual_caps_t;

#endif /* __FWUAL_TYPES_H__ */
