/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

/**
 * @file el2go_ota_diag.h
 * @brief Logging interface.
 *
 * The OTA_DIAG_* macros expand to el2go_ota_diag_emit(). The backend selected
 * via ${OS}/${DIAG_BACKEND} provides the full implementation including
 * formatting and output. A weak no-op default is compiled when no backend
 * exists for the current OS so the build always links.
 *
 * @defgroup el2go_ota_diag Logging
 * @brief Logging interface and backend contract.
 * @{
 */

#ifndef __EL2GO_OTA_DIAG_H__
#define __EL2GO_OTA_DIAG_H__

/** @brief Severity level of a log line. */
typedef enum {
    EL2GO_OTA_DIAG_LEVEL_INFO = 0,  /**< Informational message. */
    EL2GO_OTA_DIAG_LEVEL_DONE = 1,  /**< Step completed successfully. */
    EL2GO_OTA_DIAG_LEVEL_WARN = 2,  /**< Warning; operation continues. */
    EL2GO_OTA_DIAG_LEVEL_FAIL = 3,  /**< Step failed. */
    EL2GO_OTA_DIAG_LEVEL_ERROR = 4, /**< Error condition. */
} el2go_ota_diag_level_t;

/**
 * @brief Format and emit one log line.
 *
 * Implemented by the selected backend. The weak default discards the line.
 * Each backend owns its own formatting and output.
 *
 * @param[in] level  Severity level.
 * @param[in] fmt    printf-style format string. Must not be NULL.
 * @param[in] ...    Arguments for fmt.
 */
void el2go_ota_diag_emit(el2go_ota_diag_level_t level, const char *fmt, ...);

/**
 * @brief Dump stored log to console, oldest to newest.
 *
 * No-op for backends without persistent storage.
 */
void el2go_ota_diag_dump(void);

/**
 * @brief Replay persistent log at boot.
 *
 * No-op for backends without persistent storage.
 */
void el2go_ota_diag_boot_replay(void);

/** @brief Log a completed step at DONE level. */
#define OTA_DIAG_DONE(fn) el2go_ota_diag_emit(EL2GO_OTA_DIAG_LEVEL_DONE, "[DONE] " fn "\n")
/** @brief Log a failed step at FAIL level. */
#define OTA_DIAG_FAIL(fn) el2go_ota_diag_emit(EL2GO_OTA_DIAG_LEVEL_FAIL, "[FAIL] " fn "\n")
/** @brief Log an informational message at INFO level. */
#define OTA_DIAG_INFO(msg, ...) \
    el2go_ota_diag_emit(EL2GO_OTA_DIAG_LEVEL_INFO, "[INFO] " msg "\n", ##__VA_ARGS__)
/** @brief Log a warning message at WARN level. */
#define OTA_DIAG_WARN(msg, ...) \
    el2go_ota_diag_emit(EL2GO_OTA_DIAG_LEVEL_WARN, "[WARN] " msg "\n", ##__VA_ARGS__)
/** @brief Log an error message at ERROR level. */
#define OTA_DIAG_ERROR(msg, ...) \
    el2go_ota_diag_emit(EL2GO_OTA_DIAG_LEVEL_ERROR, "[ERROR] " msg "\n", ##__VA_ARGS__)

#endif /* __EL2GO_OTA_DIAG_H__ */

/** @} */ /* end of el2go_ota_diag */