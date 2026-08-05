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

/*
 * Binary data buffer (e.g. for passing a server certificate to the RTP agent)
 */
typedef struct {
    uint8_t *data; /* Pointer to data */
    size_t len;    /* Length in bytes */
} el2go_buffer_t;

/*
 * RTP Agent context
 *
 * This is an opaque structure. Users should not access its members directly.
 * The actual definition is in the implementation files.
 */
typedef struct el2go_rtp_ctx el2go_rtp_ctx_t;

/*
 * EdgeLock 2GO datastore configuration
 */
typedef struct el2go_rtp_datastore_config {
    const char *hostname;              /* Server hostname */
    uint16_t port;                     /* Server port */
    const el2go_buffer_t *certificate; /* Server certificate */
} el2go_rtp_datastore_config_t;

/**
 * el2go_rtp_get_version - Get RTP Agent version information
 * @major: Pointer to store major version number
 * @minor: Pointer to store minor version number
 *
 * Return:
 * EL2GO_STATUS_SUCCESS on success, EL2GO_STATUS_FAILURE otherwise
 */
el2go_status_t el2go_rtp_get_version(unsigned int *major, unsigned int *minor);

/**
 * el2go_rtp_init - Initialize and allocate RTP Agent context
 * @ctx: Pointer to store allocated context
 *
 * Return:
 * EL2GO_STATUS_SUCCESS on success, EL2GO_STATUS_FAILURE otherwise
 */
el2go_status_t el2go_rtp_init(el2go_rtp_ctx_t **ctx);

/**
 * el2go_rtp_free - Cleanup and free RTP Agent context
 * @ctx: Pointer to context (will be set to NULL)
 *
 * Return:
 * EL2GO_STATUS_SUCCESS on success, EL2GO_STATUS_FAILURE otherwise
 */
el2go_status_t el2go_rtp_free(el2go_rtp_ctx_t **ctx);

/**
 * el2go_rtp_add_keystore - Add a keystore to the RTP Agent
 * @ctx: RTP Agent context
 * @keystore_ctx: Keystore context to add
 *
 * Adds an initialized keystore to the RTP Agent's list of keystores.
 * The keystore must be initialized with el2go_keystore_init() first.
 *
 * Return:
 * EL2GO_STATUS_SUCCESS on success, error code otherwise
 */
el2go_status_t el2go_rtp_add_keystore(el2go_rtp_ctx_t *ctx, el2go_keystore_t *keystore_ctx);

/**
 * el2go_rtp_remove_keystore - Remove a keystore from the RTP Agent
 * @ctx: RTP Agent context
 * @keystore_ctx: Keystore context to remove
 *
 * Removes the keystore from the RTP Agent's list. The keystore context itself
 * should be freed separately using el2go_keystore_free().
 *
 * Return:
 * EL2GO_STATUS_SUCCESS on success, error code otherwise
 */
el2go_status_t el2go_rtp_remove_keystore(el2go_rtp_ctx_t *ctx, el2go_keystore_t *keystore_ctx);

/**
 * el2go_rtp_get_keystore_by_id - Get a keystore by its identifier
 * @ctx: RTP Agent context
 * @id: Keystore identifier to search for
 * @keystore: Pointer to store the found keystore
 *
 * This function searches through the registered keystores in the Agent context
 * to find a keystore with the specified identifier. If found, the keystore is
 * returned through the keystore parameter.
 *
 * Return:
 * EL2GO_STATUS_SUCCESS on success, error code otherwise
 */
el2go_status_t el2go_rtp_get_keystore_by_id(el2go_rtp_ctx_t *ctx, uint32_t id,
                                            el2go_keystore_t **keystore);

/**
 * el2go_rtp_add_datastore - Add a datastore to the RTP Agent
 * @ctx: RTP Agent context
 * @datastore: Datastore context to add
 *
 * Adds an initialized datastore to the RTP Agent's list of datastores.
 * The datastore must be initialized with el2go_datastore_init() first.
 *
 * Return:
 * EL2GO_STATUS_SUCCESS on success, error code otherwise
 */
el2go_status_t el2go_rtp_add_datastore(el2go_rtp_ctx_t *ctx, el2go_datastore_t *datastore);

/**
 * el2go_rtp_remove_datastore - Remove a datastore from the RTP Agent
 * @ctx: RTP Agent context
 * @datastore: Pointer to datastore context (will be set to NULL)
 *
 * Removes the datastore from the RTP Agent's list and frees all resources.
 *
 * Return:
 * EL2GO_STATUS_SUCCESS on success, error code otherwise
 */
el2go_status_t el2go_rtp_remove_datastore(el2go_rtp_ctx_t *ctx, el2go_datastore_t *datastore);

/**
 * el2go_rtp_get_datastore_by_id - Get a datastore by its identifier
 * @ctx: RTP Agent context
 * @id: Datastore identifier to search for
 * @datastore: Pointer to store the found datastore
 *
 * This function searches through the registered datastores in the Agent context
 * to find a datastore with the specified identifier. If found, the datastore is
 * returned through the datastore parameter.
 *
 * Return:
 * EL2GO_STATUS_SUCCESS on success, error code otherwise
 */
el2go_status_t el2go_rtp_get_datastore_by_id(el2go_rtp_ctx_t *ctx, uint32_t id,
                                             el2go_datastore_t **datastore);

/**
 * el2go_rtp_provision - Provision keys and certificates from the EdgeLock 2GO server
 * @ctx:           RTP Agent context
 * @status_report: Optional output parameter. If non-NULL, receives an opaque pointer to
 *                 the server provisioning status report on return. The caller must release
 *                 this with el2go_rtp_free_status_report() when no longer needed.
 *                 Pass NULL if the report is not required.
 *
 * Return:
 * EL2GO_STATUS_SUCCESS on success, error code otherwise
 */
el2go_status_t el2go_rtp_provision(el2go_rtp_ctx_t *ctx, void **status_report);

/**
 * el2go_rtp_free_status_report - Release a provisioning status report
 * @status_report: Pointer to the opaque report pointer returned by el2go_rtp_provision().
 *                 The pointed-to pointer is set to NULL after the call.
 *                 No-op if status_report or *status_report is NULL.
 *
 * Must be called to free any report obtained from el2go_rtp_provision() when
 * the caller has finished with it.
 */
el2go_status_t el2go_rtp_free_status_report(void **status_report);

/**
 * el2go_rtp_print_status_report - Print a provisioning status report
 * @status_report: Opaque report pointer returned by el2go_rtp_provision(), or NULL.
 *
 * Logs the overall update outcome, correlation ID, and per-subsystem details
 * (claim, RTP, CSP) using the EL2GO INFO log level.
 * Safe to call with NULL (prints "(none)").
 */
el2go_status_t el2go_rtp_print_status_report(const void *status_report);

/**
 * el2go_rtp_datastore_el2go - Configure EdgeLock 2GO datastore
 * @datastore: Datastore
 * @keystore_ctx: Keystore context for secure operations
 * @config: EdgeLock 2GO configuration
 *
 * Configures the EdgeLock 2GO datastore with connection parameters.
 * If certificate is NULL or certificate->data is NULL, compile-time defaults
 * will be used for the server certificate. Missing hostname or port will also
 * use defaults.
 *
 * Return:
 * EL2GO_STATUS_SUCCESS on success, error code otherwise
 */
el2go_status_t el2go_rtp_datastore_el2go(el2go_datastore_t *datastore,
                                         el2go_keystore_t *keystore_ctx,
                                         const el2go_rtp_datastore_config_t *config);
#endif /* __EL2GO_RTP_H__ */
