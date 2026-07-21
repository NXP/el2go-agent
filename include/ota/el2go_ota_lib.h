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
    char file_id[EL2GO_OTA_MAX_FILE_ID_LEN];
    char name[EL2GO_OTA_MAX_NAME_LEN];
    int64_t size;
    char checksum[EL2GO_OTA_MAX_CHECKSUM_LEN];
} el2go_ota_file_metadata_t;

/** @brief Parsed package entry returned by el2go_ota_check_for_updates(). */
typedef struct {
    char package_id[EL2GO_OTA_MAX_PACKAGE_ID_LEN];
    char name[EL2GO_OTA_MAX_NAME_LEN];
    char version[EL2GO_OTA_MAX_VERSION_LEN];
    el2go_ota_file_metadata_t files[EL2GO_OTA_MAX_FILE_METADATA];
    size_t file_count;
} el2go_ota_package_info_t;

/** @brief Parsed update entry returned by el2go_ota_check_for_updates(). */
typedef struct {
    char update_id[EL2GO_OTA_MAX_UPDATE_ID_LEN];
    char name[EL2GO_OTA_MAX_NAME_LEN];
    el2go_ota_package_info_t packages[EL2GO_OTA_MAX_PACKAGES];
    size_t package_count;
} el2go_ota_update_info_t;

/**
 * @brief Result returned by el2go_ota_check_for_updates().
 *
 * If update_available is true, updates[0..update_count-1] contain the parsed
 * update descriptors. first_update_id and first_package_id are convenience
 * pointers into updates[0] for the common single-update case.
 */
typedef struct {
    bool update_available;
    el2go_ota_update_info_t updates[EL2GO_OTA_MAX_UPDATES];
    size_t update_count;
    const char *first_update_id;  /**< Points into updates[0].update_id. */
    const char *first_package_id; /**< Points into updates[0].packages[0].package_id. */
} el2go_ota_check_update_resp_t;

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
 * @retval EL2GO_OTA_SUCCESS on success.
 * @retval EL2GO_OTA_ERROR_INVALID_PARAM if ctx or config is NULL, or any
 *         required config field is missing or invalid (including port == 0).
 * @retval EL2GO_OTA_ERROR_MEMORY if context allocation fails.
 * @retval EL2GO_OTA_ERROR_PLATFORM_INIT if platform (PSA crypto / secure
 *         storage) initialisation fails.
 * @retval EL2GO_OTA_ERROR_TLS_HANDSHAKE if TLS context configuration fails.
 * @retval EL2GO_OTA_ERROR_CERT_VERIFY if client credentials cannot be
 *         loaded from the keystore.
 * @retval EL2GO_OTA_ERROR_AUTH if the client private key cannot be
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
 * @retval EL2GO_OTA_SUCCESS on success (including when already connected).
 * @retval EL2GO_OTA_ERROR_INVALID_PARAM if ctx is NULL.
 * @retval EL2GO_OTA_ERROR_NETWORK if TCP connection fails.
 * @retval EL2GO_OTA_ERROR_TLS_HANDSHAKE if TLS handshake fails.
 * @retval EL2GO_OTA_ERROR_CERT_VERIFY if server certificate verification fails.
 * @retval EL2GO_OTA_ERROR_AUTH if client authentication fails.
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
 * @retval EL2GO_OTA_SUCCESS on success.
 * @retval EL2GO_OTA_ERROR_INVALID_PARAM if ctx is NULL.
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
 * @retval true  if connected.
 * @retval false if not connected, not initialised, or ctx is NULL.
 */
bool el2go_ota_is_connected(const el2go_ota_ctx_t *ctx);

/**
 * @brief Convert an EL2GO OTA status code to a human-readable string.
 *
 * @param[in] status  Status code to translate.
 *
 * @retval Null-terminated, human-readable description. Never returns NULL.
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
 * @retval EL2GO_OTA_SUCCESS on success.
 * @retval EL2GO_OTA_ERROR_INVALID_PARAM if ctx or out_resp is NULL.
 * @retval EL2GO_OTA_ERROR_NETWORK if not connected or a network error occurs.
 * @retval EL2GO_OTA_ERROR_ENCODE if request encoding fails.
 * @retval EL2GO_OTA_ERROR_DECODE if response parsing fails.
 * @retval EL2GO_OTA_ERROR_SERVER if the server returns a non-zero gRPC status.
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
 * @retval EL2GO_OTA_SUCCESS on success.
 * @retval EL2GO_OTA_ERROR_INVALID_PARAM if ctx, update_id, package_id, or
 *         chunk_cb is NULL.
 * @retval EL2GO_OTA_ERROR_NETWORK if not connected or a network error occurs
 *         after all retries.
 * @retval EL2GO_OTA_ERROR_ENCODE if request encoding fails.
 * @retval EL2GO_OTA_ERROR_DECODE if response parsing fails.
 * @retval EL2GO_OTA_ERROR_SERVER if the server returns a non-zero gRPC status.
 * @retval Any non-zero status returned by chunk_cb.
 */
el2go_ota_status_t el2go_ota_download_package(
    el2go_ota_ctx_t *ctx, const char *update_id, const char *package_id, size_t resume_offset,
    el2go_ota_status_t (*chunk_cb)(const uint8_t *data, size_t len, size_t offset, void *cb_ctx),
    void *cb_ctx);

#endif /* __EL2GO_OTA_LIB_H__ */
