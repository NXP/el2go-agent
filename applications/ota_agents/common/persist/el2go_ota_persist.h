/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

/**
 * @file el2go_ota_persist.h
 * @brief Agent state persistence across reboot and power loss.
 *
 * Declares the interface used by the OTA agent to persist its update state so
 * the next boot can report the outcome (SUCCESS, FAILURE, or ROLLBACK) to the
 * server. This header defines the generic contract that every backend must
 * honor; the symbols carry weak defaults that are RAM-only, so a build links
 * without a concrete backend. See the zephyr/ backend for the non-volatile
 * implementation.
 *
 * @defgroup el2go_ota_persist State Persistence Abstraction
 * @brief Agent state persistence contract.
 * @{
 */

#ifndef __EL2GO_OTA_PERSIST_H__
#define __EL2GO_OTA_PERSIST_H__

#include <stdint.h>

#include "ota/el2go_ota_lib.h"

/** @brief Agent update state machine. */
typedef enum {
    AGENT_STATE_IDLE = 0, /**< Idle; no update in progress. */
    AGENT_STATE_CHECK,    /**< Checking the server for available updates. */
    AGENT_STATE_DOWNLOAD, /**< Downloading the update package. */
    AGENT_STATE_INSTALL,  /**< Installing the downloaded firmware. */
    AGENT_STATE_REBOOT,   /**< Rebooting to activate the new firmware. */
    AGENT_STATE_FINALIZE, /**< Finalizing and reporting the outcome. */
} agent_state_t;

/**
 * @brief Persisted record kept across reboots.
 *
 * Identifies the update/package currently being applied so the next boot can
 * report SUCCESS, FAILURE or ROLLBACK to the server. Download resume is
 * handled in-session only (see updater.c) and does not rely on any persisted
 * offset.
 */
typedef struct {
    uint32_t state;                                /**< agent_state_t value. */
    char update_id[EL2GO_OTA_MAX_UPDATE_ID_LEN];   /**< Null-terminated update identifier. */
    char package_id[EL2GO_OTA_MAX_PACKAGE_ID_LEN]; /**< Null-terminated package identifier. */
    uint8_t valid; /**< EL2GO_OTA_PERSIST_VALID_MAGIC when the record is live. */
} agent_persist_t;

/** @brief Value of the valid field that marks a live record. */
#define EL2GO_OTA_PERSIST_VALID_MAGIC 0x5AU

/**
 * @brief Result of a persistence operation.
 *
 * Self-documenting status codes returned by the persistence API. All error
 * codes are negative and success is 0, so existing "!= 0" checks continue to
 * treat any error as failure.
 */
typedef enum {
    EL2GO_OTA_PERSIST_OK = 0,             /**< Operation succeeded. */
    EL2GO_OTA_PERSIST_ERR_ARG = -1,       /**< Invalid argument (NULL pointer). */
    EL2GO_OTA_PERSIST_ERR_NOT_READY = -2, /**< Backend storage device not present or not ready. */
    EL2GO_OTA_PERSIST_ERR_MOUNT = -3,     /**< Storage geometry query or mount failed. */
    EL2GO_OTA_PERSIST_ERR_IO = -4,        /**< Read, write, or delete operation failed. */
    EL2GO_OTA_PERSIST_ERR_PARTIAL = -5,   /**< Write stored fewer bytes than requested. */
} el2go_ota_persist_status_t;

/**
 * @brief Load the persisted record.
 *
 * Reads the stored record into out. If no record is stored, out->valid is set
 * to 0.
 *
 * @param[out] out  Receives the loaded record. Must not be NULL.
 *
 * @return EL2GO_OTA_PERSIST_OK on success (including when no record is stored).
 * @return EL2GO_OTA_PERSIST_ERR_ARG if out is NULL.
 * @return EL2GO_OTA_PERSIST_ERR_NOT_READY if the storage device is not ready.
 * @return EL2GO_OTA_PERSIST_ERR_MOUNT if the storage cannot be mounted.
 * @return EL2GO_OTA_PERSIST_ERR_IO if the read fails.
 */
el2go_ota_persist_status_t el2go_ota_persist_read(agent_persist_t *out);

/**
 * @brief Save the persisted record.
 *
 * @param[in] in  Record to store. Must not be NULL.
 *
 * @return EL2GO_OTA_PERSIST_OK on success.
 * @return EL2GO_OTA_PERSIST_ERR_ARG if in is NULL.
 * @return EL2GO_OTA_PERSIST_ERR_NOT_READY if the storage device is not ready.
 * @return EL2GO_OTA_PERSIST_ERR_MOUNT if the storage cannot be mounted.
 * @return EL2GO_OTA_PERSIST_ERR_IO if the write fails.
 * @return EL2GO_OTA_PERSIST_ERR_PARTIAL if fewer bytes than requested were stored.
 */
el2go_ota_persist_status_t el2go_ota_persist_write(const agent_persist_t *in);

/**
 * @brief Clear the stored record.
 *
 * @return EL2GO_OTA_PERSIST_OK on success (including when no record was present).
 * @return EL2GO_OTA_PERSIST_ERR_NOT_READY if the storage device is not ready.
 * @return EL2GO_OTA_PERSIST_ERR_MOUNT if the storage cannot be mounted.
 * @return EL2GO_OTA_PERSIST_ERR_IO if the delete fails.
 */
el2go_ota_persist_status_t el2go_ota_persist_clear(void);

#endif /* __EL2GO_OTA_PERSIST_H__ */

/** @} */ /* end of el2go_ota_persist */
