/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef __EL2GO_OTA_LIB_H__
#define __EL2GO_OTA_LIB_H__

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "ota/el2go_ota_config.h"

/* String field size limits (including null terminator). */
#define EL2GO_OTA_MAX_UPDATE_ID_LEN 64U
#define EL2GO_OTA_MAX_PACKAGE_ID_LEN 64U
#define EL2GO_OTA_MAX_FILE_ID_LEN 64U
#define EL2GO_OTA_MAX_NAME_LEN 128U
#define EL2GO_OTA_MAX_VERSION_LEN 32U
#define EL2GO_OTA_MAX_CHECKSUM_LEN 128U

/* Maximum entries per level of the update hierarchy. */
#define EL2GO_OTA_MAX_UPDATES 4U
#define EL2GO_OTA_MAX_PACKAGES 4U
#define EL2GO_OTA_MAX_FILE_METADATA 8U

/* Magic byte stored in el2go_ota_pending_status_t.valid to mark a live entry. */
#define EL2GO_OTA_STATUS_VALID_MAGIC 0xA5U

/**
 * @brief Status codes returned by EL2GO OTA Library functions.
 */
typedef enum {
    EL2GO_OTA_SUCCESS,             /**< Operation succeeded. */
    EL2GO_OTA_ERROR_INVALID_PARAM, /**< NULL or invalid parameter. */
    EL2GO_OTA_ERROR_MEMORY,        /**< Heap allocation failed. */
    EL2GO_OTA_ERROR_AUTH,          /**< Client authentication failed. */
    EL2GO_OTA_ERROR_NETWORK,       /**< TCP connection failed. */
    EL2GO_OTA_ERROR_TLS_HANDSHAKE, /**< TLS handshake failed. */
    EL2GO_OTA_ERROR_CERT_VERIFY,   /**< Server certificate verification failed. */
    EL2GO_OTA_ERROR_PLATFORM_INIT, /**< Platform initialisation failed. */
    EL2GO_OTA_ERROR_ENCODE,        /**< Protobuf request encoding failed. */
    EL2GO_OTA_ERROR_DECODE,        /**< Protobuf response decoding failed. */
    EL2GO_OTA_ERROR_SERVER,        /**< Server returned a non-zero gRPC status code. */
    EL2GO_OTA_ERROR_INTERNAL,      /**< Unexpected internal error (e.g. buffer encoding). */
} el2go_ota_status_t;

/**
 * @brief Opaque EL2GO OTA Library context.
 *
 * Allocated by el2go_ota_init(), freed by el2go_ota_cleanup().
 * Callers must not inspect or modify the internals.
 */
typedef struct el2go_ota_ctx el2go_ota_ctx_t;

/**
 * @brief A single key-value attribute pair for device metadata.
 *
 * Used in el2go_ota_check_for_updates() to pass device attributes to the
 * OTA server. Both pointers must remain valid for the duration of the call.
 */
typedef struct {
    const char *key;   /**< Attribute name (null-terminated). Must not be NULL. */
    const char *value; /**< Attribute value (null-terminated). Must not be NULL. */
} el2go_ota_attr_t;

/** @brief Parsed file metadata entry returned by el2go_ota_check_for_updates(). */
typedef struct {
    char file_id[EL2GO_OTA_MAX_FILE_ID_LEN];   /**< Null-terminated file identifier. */
    char name[EL2GO_OTA_MAX_NAME_LEN];         /**< Null-terminated human-readable file name. */
    int64_t size;                              /**< File size in bytes. */
    char checksum[EL2GO_OTA_MAX_CHECKSUM_LEN]; /**< Null-terminated checksum string. */
} el2go_ota_file_metadata_t;

/** @brief Parsed package entry returned by el2go_ota_check_for_updates(). */
typedef struct {
    char package_id[EL2GO_OTA_MAX_PACKAGE_ID_LEN]; /**< Null-terminated package identifier. */
    char name[EL2GO_OTA_MAX_NAME_LEN];       /**< Null-terminated human-readable package name. */
    char version[EL2GO_OTA_MAX_VERSION_LEN]; /**< Null-terminated package version string. */
    el2go_ota_file_metadata_t
        files[EL2GO_OTA_MAX_FILE_METADATA]; /**< Array of file metadata entries. */
    size_t file_count;                      /**< Number of valid entries in files[]. */
} el2go_ota_package_info_t;

/** @brief Parsed update entry returned by el2go_ota_check_for_updates(). */
typedef struct {
    char update_id[EL2GO_OTA_MAX_UPDATE_ID_LEN]; /**< Null-terminated update identifier. */
    char name[EL2GO_OTA_MAX_NAME_LEN];           /**< Null-terminated human-readable update name. */
    el2go_ota_package_info_t packages[EL2GO_OTA_MAX_PACKAGES]; /**< Array of package entries. */
    size_t package_count; /**< Number of valid entries in packages[]. */
} el2go_ota_update_info_t;

/**
 * @brief Result returned by el2go_ota_check_for_updates().
 *
 * If update_available is true, updates[0..update_count-1] contain the parsed
 * update descriptors. first_update_id and first_package_id are convenience
 * pointers into updates[0] for the common single-update case.
 */
typedef struct {
    bool update_available; /**< true if at least one update is available. */
    el2go_ota_update_info_t
        updates[EL2GO_OTA_MAX_UPDATES]; /**< Array of parsed update descriptors. */
    size_t update_count;                /**< Number of valid entries in updates[]. */
    const char *first_update_id;        /**< Points into updates[0].update_id. */
    const char *first_package_id;       /**< Points into updates[0].packages[0].package_id. */
} el2go_ota_check_update_resp_t;

/**
 * @brief OTA update outcome status for reporting to the EL2GO backend.
 */
typedef enum {
    EL2GO_OTA_OUTCOME_SUCCESS = 0,  /**< Firmware installed and confirmed by MCUBoot. */
    EL2GO_OTA_OUTCOME_FAILURE = 1,  /**< Firmware installation failed. */
    EL2GO_OTA_OUTCOME_ROLLBACK = 2, /**< MCUBoot rolled back to the previous image. */
} el2go_ota_update_outcome_t;

/**
 * @brief NVS-persisted pending status record.
 *
 * Read back via el2go_ota_get_pending_status(). The valid field equals
 * EL2GO_OTA_STATUS_VALID_MAGIC when a live entry is present; any other value
 * means the entry does not exist or has already been delivered.
 */
typedef struct {
    uint8_t outcome;                             /**< el2go_ota_update_outcome_t cast to uint8_t */
    char update_id[EL2GO_OTA_MAX_UPDATE_ID_LEN]; /**< null-terminated update identifier */
    char package_id[EL2GO_OTA_MAX_PACKAGE_ID_LEN]; /**< null-terminated package identifier */
    uint8_t valid;                                 /**< EL2GO_OTA_STATUS_VALID_MAGIC = live entry */
} el2go_ota_pending_status_t;

/**
 * @brief Allocate a context and prepare the mTLS security layer.
 *
 * Retrieves client credentials from the platform keystore using the object
 * IDs in config, configures the TLS context via the net_crypto abstraction
 * layer, and validates that credentials are present and well-formed.
 *
 * Does NOT open a network connection -- call el2go_ota_connect() for that.
 *
 * @param[out] ctx     Receives the allocated context pointer. Must not be NULL.
 *                     On failure *ctx is set to NULL.
 * @param[in]  config  mTLS configuration. Must not be NULL.
 *                     config->hostname must not be NULL.
 *                     config->port must not be 0.
 *                     config->server_ca_chain must not be NULL and
 *                     config->server_ca_chain_size must be > 0.
 *
 * @return EL2GO_OTA_SUCCESS on success.
 * @return EL2GO_OTA_ERROR_INVALID_PARAM if ctx or config is NULL, or any
 *         required config field is missing or invalid (including port == 0).
 * @return EL2GO_OTA_ERROR_MEMORY if context allocation fails.
 * @return EL2GO_OTA_ERROR_PLATFORM_INIT if platform (PSA crypto / secure
 *         storage) initialisation fails.
 * @return EL2GO_OTA_ERROR_TLS_HANDSHAKE if TLS context configuration fails.
 * @return EL2GO_OTA_ERROR_CERT_VERIFY if client credentials cannot be
 *         loaded from the keystore.
 * @return EL2GO_OTA_ERROR_AUTH if the client private key cannot be
 *         associated.
 */
el2go_ota_status_t el2go_ota_init(el2go_ota_ctx_t **ctx, const el2go_ota_mtls_config_t *config);

/**
 * @brief Open an mTLS connection to the OTA server.
 *
 * Performs the full TLS handshake:
 * -# TCP connect to hostname:port.
 * -# Server certificate verified against server_ca_chain.
 * -# Client presents certificate (from client_cert_object_id).
 * -# Client signs CertificateVerify using private key -- signing happens
 *    inside the secure element; the key never leaves the keystore.
 * -# Server verifies signature -- mTLS connection established.
 *
 * If the context is already connected this function is a no-op and returns
 * EL2GO_OTA_SUCCESS immediately without performing a second handshake.
 *
 * @param[in] ctx  Initialised context from el2go_ota_init(). Must not be NULL.
 *
 * @return EL2GO_OTA_SUCCESS on success (including when already connected).
 * @return EL2GO_OTA_ERROR_INVALID_PARAM if ctx is NULL.
 * @return EL2GO_OTA_ERROR_NETWORK if TCP connection fails.
 * @return EL2GO_OTA_ERROR_TLS_HANDSHAKE if TLS handshake fails.
 * @return EL2GO_OTA_ERROR_CERT_VERIFY if server certificate verification fails.
 * @return EL2GO_OTA_ERROR_AUTH if client authentication fails.
 */
el2go_ota_status_t el2go_ota_connect(el2go_ota_ctx_t *ctx);

/**
 * @brief Close the mTLS connection gracefully.
 *
 * Sends a TLS close_notify alert and closes the TCP socket. The context
 * remains valid -- call el2go_ota_connect() to reconnect. Safe to call when
 * not connected (no-op).
 *
 * @param[in] ctx  Context. Must not be NULL.
 *
 * @return EL2GO_OTA_SUCCESS on success.
 * @return EL2GO_OTA_ERROR_INVALID_PARAM if ctx is NULL.
 */
el2go_ota_status_t el2go_ota_disconnect(el2go_ota_ctx_t *ctx);

/**
 * @brief Disconnect and free all resources held by the context.
 *
 * Disconnects if connected, releases the TLS context and all heap
 * allocations, then sets *ctx to NULL. Safe to call with *ctx == NULL (no-op).
 *
 * @param[in,out] ctx  Pointer to context pointer. Must not be NULL.
 */
void el2go_ota_cleanup(el2go_ota_ctx_t **ctx);

/**
 * @brief Query whether an mTLS connection is currently open.
 *
 * @param[in] ctx  Context. May be NULL (returns false).
 *
 * @return true  if connected.
 * @return false if not connected, not initialised, or ctx is NULL.
 */
bool el2go_ota_is_connected(const el2go_ota_ctx_t *ctx);

/**
 * @brief Convert an EL2GO OTA status code to a human-readable string.
 *
 * @param[in] status  Status code to translate.
 *
 * @return Null-terminated, human-readable description. Never returns NULL.
 */
const char *el2go_ota_get_error_string(el2go_ota_status_t status);

/**
 * @brief Query the OTA server for available firmware updates.
 *
 * Sends a GetAvailableUpdates request over the established connection and
 * parses the response into out_resp.
 *
 * @param[in]  ctx         Connected context. Must not be NULL.
 * @param[in]  attrs       Array of device attribute key-value pairs. May be
 *                         NULL if attr_count is 0.
 * @param[in]  attr_count  Number of entries in attrs[].
 * @param[out] out_resp    Receives the parsed response. Must not be NULL.
 *
 * @return EL2GO_OTA_SUCCESS on success.
 * @return EL2GO_OTA_ERROR_INVALID_PARAM if ctx or out_resp is NULL.
 * @return EL2GO_OTA_ERROR_NETWORK if not connected or a network error occurs.
 * @return EL2GO_OTA_ERROR_ENCODE if request encoding fails.
 * @return EL2GO_OTA_ERROR_DECODE if response parsing fails.
 * @return EL2GO_OTA_ERROR_SERVER if the server returns a non-zero gRPC status.
 */
el2go_ota_status_t el2go_ota_check_for_updates(el2go_ota_ctx_t *ctx, const el2go_ota_attr_t *attrs,
                                               size_t attr_count,
                                               el2go_ota_check_update_resp_t *out_resp);

/**
 * @brief Download a firmware package from the OTA server.
 *
 * Requests the package identified by update_id/package_id in
 * EL2GO_OTA_CHUNK_SIZE-byte chunks and delivers each chunk to chunk_cb.
 * Supports resumable downloads via resume_offset.
 *
 * @param[in] ctx            Connected context. Must not be NULL.
 * @param[in] update_id      Update identifier string. Must not be NULL.
 * @param[in] package_id     Package identifier string. Must not be NULL.
 * @param[in] resume_offset  Byte offset to resume from (0 = start fresh).
 * @param[in] chunk_cb       Callback invoked for each received data chunk.
 *                           Must not be NULL. Returning a non-zero status
 *                           aborts the download immediately.
 * @param[in] cb_ctx         Opaque user context passed to chunk_cb. May be NULL.
 *
 * @return EL2GO_OTA_SUCCESS on success.
 * @return EL2GO_OTA_ERROR_INVALID_PARAM if ctx, update_id, package_id, or
 *         chunk_cb is NULL.
 * @return EL2GO_OTA_ERROR_NETWORK if not connected or a network error occurs
 *         after all retries.
 * @return EL2GO_OTA_ERROR_ENCODE if request encoding fails.
 * @return EL2GO_OTA_ERROR_DECODE if response parsing fails.
 * @return EL2GO_OTA_ERROR_SERVER if the server returns a non-zero gRPC status.
 * @return Any non-zero status returned by chunk_cb.
 */
el2go_ota_status_t el2go_ota_download_package(
    el2go_ota_ctx_t *ctx, const char *update_id, const char *package_id, size_t resume_offset,
    el2go_ota_status_t (*chunk_cb)(const uint8_t *data, size_t len, size_t offset, void *cb_ctx),
    void *cb_ctx);

/**
 * @brief Report the OTA update outcome to the EL2GO backend.
 *
 * Persists the status to NVS before attempting delivery, so the report
 * survives a reboot if the backend is unreachable. On successful delivery
 * the NVS entry is cleared. On failure the entry is retained for retry
 * via el2go_ota_report_pending_status().
 *
 * The library must be initialised and connected before calling this function.
 *
 * @param[in] ctx        Connected context. Must not be NULL.
 * @param[in] update_id  Update identifier from the check_for_updates response.
 *                       Must not be NULL.
 * @param[in] package_id Package identifier from the check_for_updates response.
 *                       Must not be NULL.
 * @param[in] outcome    Outcome of the firmware update attempt.
 *
 * @return EL2GO_OTA_SUCCESS on success (backend acknowledged).
 * @return EL2GO_OTA_ERROR_INVALID_PARAM if ctx, update_id, or package_id is
 *         NULL, or outcome is not a valid el2go_ota_update_outcome_t value.
 * @return EL2GO_OTA_ERROR_NETWORK if not connected or delivery failed
 *         (NVS entry retained for retry).
 * @return EL2GO_OTA_ERROR_SERVER on server error response.
 * @return EL2GO_OTA_ERROR_INTERNAL on NVS, encoding, or decoding failure.
 */
el2go_ota_status_t el2go_ota_report_status(el2go_ota_ctx_t *ctx, const char *update_id,
                                           const char *package_id,
                                           el2go_ota_update_outcome_t outcome);

/**
 * @brief Schedule an OTA update status report to be delivered on the next boot.
 *
 * Persists the update outcome to NVS without attempting network delivery.
 * This function does not require an active connection and is intended to be
 * called before rebooting after fwual_activate(). On the next boot, call
 * el2go_ota_report_pending_status() to deliver the report once connected.
 *
 * @param[in] update_id   Update identifier from the check_for_updates response.
 *                        Must not be NULL.
 * @param[in] package_id  Package identifier from the check_for_updates response.
 *                        Must not be NULL.
 * @param[in] outcome     Outcome of the firmware update attempt.
 *
 * @return EL2GO_OTA_SUCCESS on success (entry written to NVS).
 * @return EL2GO_OTA_ERROR_INVALID_PARAM if update_id or package_id is NULL,
 *         or outcome is not a valid el2go_ota_update_outcome_t value.
 * @return EL2GO_OTA_ERROR_INTERNAL on KVS init or write failure.
 */
el2go_ota_status_t el2go_ota_schedule_status_report(const char *update_id, const char *package_id,
                                                    el2go_ota_update_outcome_t outcome);

/**
 * @brief Read the pending status entry from NVS without delivering it.
 *
 * Allows the caller to inspect a status report that was previously written by
 * el2go_ota_schedule_status_report() but not yet delivered. The typical use
 * case is Boot N+1 rollback detection: the agent reads the entry, overrides
 * the outcome to EL2GO_OTA_OUTCOME_ROLLBACK, rewrites it via
 * el2go_ota_schedule_status_report(), then delivers it with
 * el2go_ota_report_pending_status().
 *
 * Returns EL2GO_OTA_SUCCESS with out->valid == 0 if no entry exists.
 * Does not require an active network connection. No ctx needed.
 *
 * @param[out] out  Receives the pending entry. Must not be NULL.
 *
 * @return EL2GO_OTA_SUCCESS on success (out->valid indicates whether an
 *         entry was found: EL2GO_OTA_STATUS_VALID_MAGIC = live entry, 0 = none).
 * @return EL2GO_OTA_ERROR_INVALID_PARAM if out is NULL.
 * @return EL2GO_OTA_ERROR_INTERNAL on KVS init or read failure.
 */
el2go_ota_status_t el2go_ota_get_pending_status(el2go_ota_pending_status_t *out);

/**
 * @brief Deliver any pending status report that was not yet acknowledged.
 *
 * Reads the NVS-persisted pending status (if any) and attempts delivery.
 * If no pending status exists, returns EL2GO_OTA_SUCCESS immediately.
 * On successful delivery the NVS entry is cleared.
 * On failure the NVS entry is retained for the next retry.
 *
 * Call this function at OTA Agent startup to handle status reports that
 * survived a reboot due to a previous network failure.
 *
 * The library must be initialised and connected before calling this function.
 *
 * @param[in] ctx  Connected context. Must not be NULL.
 *
 * @return EL2GO_OTA_SUCCESS if no pending status exists, or if the pending
 *         status was successfully delivered.
 * @return EL2GO_OTA_ERROR_INVALID_PARAM if ctx is NULL.
 * @return EL2GO_OTA_ERROR_NETWORK if not connected or delivery failed
 *         (entry retained).
 * @return EL2GO_OTA_ERROR_SERVER on server error response.
 * @return EL2GO_OTA_ERROR_INTERNAL on NVS, encoding, or decoding failure.
 */
el2go_ota_status_t el2go_ota_report_pending_status(el2go_ota_ctx_t *ctx);

#endif /* __EL2GO_OTA_LIB_H__ */
