/*
 * Copyright 2018-2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef __EL2GO_RTP_H__
#define __EL2GO_RTP_H__

#include <stdint.h>
#include <stdbool.h>
#include "common/el2go_status.h"
#include "common/el2go_datastore.h"
#include "common/el2go_keystore.h"
#include "common/el2go_platform.h"

/**
 * @defgroup el2go_rtp_pub RTP Public API
 * @brief Public interface for the EdgeLock 2GO Remote Trust Provisioning agent.
 * @{
 */

/**
 * @brief Binary data buffer (e.g. for passing a server certificate to the RTP agent).
 */
typedef struct {
    uint8_t *data; /**< Pointer to data */
    size_t len;    /**< Length in bytes */
} el2go_buffer_t;

/**
 * @brief RTP Agent context (opaque).
 *
 * Users should not access its members directly.
 * The actual definition is in the implementation files.
 */
typedef struct el2go_rtp_ctx el2go_rtp_ctx_t;

/**
 * @brief EdgeLock 2GO datastore configuration.
 */
typedef struct el2go_rtp_datastore_config {
    const char *hostname;              /**< Server hostname */
    uint16_t port;                     /**< Server port */
    const el2go_buffer_t *certificate; /**< Server certificate */
} el2go_rtp_datastore_config_t;

/**
 * @brief Return the version of the EL2GO RTP library.
 *
 * @param[out] major  Pointer to store major version number. Must not be NULL.
 * @param[out] minor  Pointer to store minor version number. Must not be NULL.
 * @param[out] patch  Pointer to store patch version number. Must not be NULL.
 *
 * @retval EL2GO_STATUS_SUCCESS            Version filled successfully.
 * @retval EL2GO_STATUS_INVALID_PARAMETER  At least one output pointer is NULL.
 */
el2go_status_t el2go_rtp_get_version(unsigned int *major, unsigned int *minor, unsigned int *patch);

/**
 * @brief Initialize and allocate RTP Agent context.
 *
 * @param[out] ctx Pointer to store allocated context
 *
 * @return EL2GO_STATUS_SUCCESS on success, EL2GO_STATUS_FAILURE otherwise
 */
el2go_status_t el2go_rtp_init(el2go_rtp_ctx_t **ctx);

/**
 * @brief Cleanup and free RTP Agent context.
 *
 * @param[in,out] ctx Pointer to context (will be set to NULL)
 *
 * @return EL2GO_STATUS_SUCCESS on success, EL2GO_STATUS_FAILURE otherwise
 */
el2go_status_t el2go_rtp_free(el2go_rtp_ctx_t **ctx);

/**
 * @brief Add a keystore to the RTP Agent.
 *
 * Adds an initialized keystore to the RTP Agent's list of keystores.
 * The keystore must be initialized with el2go_keystore_init() first.
 *
 * @param[in] ctx          RTP Agent context
 * @param[in] keystore_ctx Keystore context to add
 *
 * @return EL2GO_STATUS_SUCCESS on success, error code otherwise
 */
el2go_status_t el2go_rtp_add_keystore(el2go_rtp_ctx_t *ctx, el2go_keystore_t *keystore_ctx);

/**
 * @brief Remove a keystore from the RTP Agent.
 *
 * Removes the keystore from the RTP Agent's list. The keystore context itself
 * should be freed separately using el2go_keystore_free().
 *
 * @param[in] ctx          RTP Agent context
 * @param[in] keystore_ctx Keystore context to remove
 *
 * @return EL2GO_STATUS_SUCCESS on success, error code otherwise
 */
el2go_status_t el2go_rtp_remove_keystore(el2go_rtp_ctx_t *ctx, el2go_keystore_t *keystore_ctx);

/**
 * @brief Get a keystore by its identifier.
 *
 * Searches through the registered keystores in the Agent context to find a
 * keystore with the specified identifier. If found, the keystore is returned
 * through the @p keystore parameter.
 *
 * @param[in]  ctx      RTP Agent context
 * @param[in]  id       Keystore identifier to search for
 * @param[out] keystore Pointer to store the found keystore
 *
 * @return EL2GO_STATUS_SUCCESS on success, error code otherwise
 */
el2go_status_t el2go_rtp_get_keystore_by_id(el2go_rtp_ctx_t *ctx, uint32_t id,
                                            el2go_keystore_t **keystore);

/**
 * @brief Add a datastore to the RTP Agent.
 *
 * Adds an initialized datastore to the RTP Agent's list of datastores.
 * The datastore must be initialized with el2go_datastore_init() first.
 *
 * @param[in] ctx       RTP Agent context
 * @param[in] datastore Datastore context to add
 *
 * @return EL2GO_STATUS_SUCCESS on success, error code otherwise
 */
el2go_status_t el2go_rtp_add_datastore(el2go_rtp_ctx_t *ctx, el2go_datastore_t *datastore);

/**
 * @brief Remove a datastore from the RTP Agent.
 *
 * Removes the datastore from the RTP Agent's list and frees all resources.
 *
 * @param[in] ctx       RTP Agent context
 * @param[in] datastore Datastore context to remove
 *
 * @return EL2GO_STATUS_SUCCESS on success, error code otherwise
 */
el2go_status_t el2go_rtp_remove_datastore(el2go_rtp_ctx_t *ctx, el2go_datastore_t *datastore);

/**
 * @brief Get a datastore by its identifier.
 *
 * Searches through the registered datastores in the Agent context to find a
 * datastore with the specified identifier. If found, the datastore is returned
 * through the @p datastore parameter.
 *
 * @param[in]  ctx       RTP Agent context
 * @param[in]  id        Datastore identifier to search for
 * @param[out] datastore Pointer to store the found datastore
 *
 * @return EL2GO_STATUS_SUCCESS on success, error code otherwise
 */
el2go_status_t el2go_rtp_get_datastore_by_id(el2go_rtp_ctx_t *ctx, uint32_t id,
                                             el2go_datastore_t **datastore);

/**
 * @brief Provision keys and certificates from the EdgeLock 2GO server.
 *
 * @param[in]  ctx           RTP Agent context
 * @param[out] status_report Optional. If non-NULL, receives an opaque pointer to
 *                           the server provisioning status report on return. The
 *                           caller must release this with el2go_rtp_free_status_report()
 *                           when no longer needed. Pass NULL if not required.
 *
 * @return EL2GO_STATUS_SUCCESS on success, error code otherwise
 */
el2go_status_t el2go_rtp_provision(el2go_rtp_ctx_t *ctx, void **status_report);

/**
 * @brief Release a provisioning status report.
 *
 * Must be called to free any report obtained from el2go_rtp_provision() when
 * the caller has finished with it. The pointed-to pointer is set to NULL after
 * the call. No-op if @p status_report or *status_report is NULL.
 *
 * @param[in,out] status_report Pointer to the opaque report pointer returned by
 *                              el2go_rtp_provision()
 */
el2go_status_t el2go_rtp_free_status_report(void **status_report);

/**
 * @brief Print a provisioning status report.
 *
 * Logs the overall update outcome, correlation ID, and per-subsystem details
 * (claim, RTP, CSP) using the EL2GO INFO log level.
 * Safe to call with NULL (prints "(none)").
 *
 * @param[in] status_report Opaque report pointer returned by el2go_rtp_provision(), or NULL
 */
el2go_status_t el2go_rtp_print_status_report(const void *status_report);

/**
 * @brief Configure EdgeLock 2GO datastore.
 *
 * Configures the EdgeLock 2GO datastore with connection parameters.
 * If @p certificate is NULL or certificate->data is NULL, compile-time defaults
 * will be used for the server certificate. Missing hostname or port will also
 * use defaults.
 *
 * @param[in] datastore    Datastore
 * @param[in] keystore_ctx Keystore context for secure operations
 * @param[in] config       EdgeLock 2GO configuration
 *
 * @return EL2GO_STATUS_SUCCESS on success, error code otherwise
 */
el2go_status_t el2go_rtp_datastore_el2go(el2go_datastore_t *datastore,
                                         el2go_keystore_t *keystore_ctx,
                                         const el2go_rtp_datastore_config_t *config);
/** @} */ /* end of el2go_rtp_pub */

#endif /* __EL2GO_RTP_H__ */
