/*
 * Copyright 2018-2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef __EL2GO_KEYSTORE_H__
#define __EL2GO_KEYSTORE_H__

#include <stdint.h>
#include "common/el2go_status.h"

typedef struct el2go_platform_ctx el2go_platform_ctx_t;

/*
* Keystore types
*/
typedef enum {
    EL2GO_KEYSTORE_SSS, /* SSS (Secure Subsystem) keystore */
    EL2GO_KEYSTORE_PSA  /* PSA (Platform Security Architecture) keystore */
} el2go_keystore_type_t;

/**
 * IoT Agent keystore
 *
 * This structure contains fields used to manage keystores. Some fields are
 * used by the keystore implementations (context) and others are used for
 * managing the keystores by the internal implementation. Some of them are
 * public fields (like id, type) and some of them are private (priv).
 *
 * Users should only access and modify the public fields and the context field
 * for keystore implementations. The priv field is for internal use only and
 * must not be accessed or modified by users.
 */
typedef struct el2go_keystore {
    uint32_t id;                        /* Keystore identifier */
    el2go_keystore_type_t type;         /* Keystore type (SSS or PSA) */
    void *context;                      /* Keystore context */
    void *priv;                         /* Private data */
    el2go_platform_ctx_t *platform_ctx; /* Platform context */
} el2go_keystore_t;

/**
 * el2go_keystore_init - Initialize a keystore
 * @id: Keystore identifier
 * @platform_ctx: Platform context for hardware access
 * @keystore: Pointer to keystore structure
 *
 * This function initializes a keystore with the specified platform
 * and type.
 *
 * Return:
 * EL2GO_STATUS_SUCCESS on success, error code otherwise
 */
el2go_status_t el2go_keystore_init(uint32_t id, el2go_platform_ctx_t *platform_ctx,
                                   el2go_keystore_t *keystore);

/**
 * el2go_keystore_free - Free a keystore
 * @keystore: Pointer to keystore structure
 *
 * This function frees all resources associated with the keystore.
 *
 * Return:
 * EL2GO_STATUS_SUCCESS on success, error code otherwise
 */
el2go_status_t el2go_keystore_free(el2go_keystore_t *keystore);

/**
 * el2go_keystore_open_session - Open a session with the keystore
 * @keystore: Keystore structure
 *
 * This function opens a session with the underlying secure element or
 * keystore backend. A session must be opened before performing cryptographic
 * operations. For PSA keystores, this may initialize the crypto subsystem.
 * For SSS keystores, this establishes communication with the secure element.
 *
 * Return:
 * EL2GO_STATUS_SUCCESS on success, error code otherwise
 */
el2go_status_t el2go_keystore_open_session(el2go_keystore_t *keystore);

/**
 * el2go_keystore_close_session - Close a session with the keystore
 * @keystore: Keystore structure
 *
 * This function closes an active session with the keystore. All pending
 * operations should be completed before closing the session. After closing,
 * a new session must be opened to perform additional operations.
 *
 * Return:
 * EL2GO_STATUS_SUCCESS on success, error code otherwise
 */
el2go_status_t el2go_keystore_close_session(el2go_keystore_t *keystore);

/**
 * el2go_keystore_handle_request - Handle a keystore request
 * @keystore: Keystore structure
 * @istream: Input stream with request data
 * @ostream: Output stream for response data
 * @message_type: Message type fields
 *
 * This function handles incoming requests for keystore operations.
 *
 * Return:
 * EL2GO_STATUS_SUCCESS on success, error code otherwise
 */
el2go_status_t el2go_keystore_handle_request(el2go_keystore_t *keystore, const void *message_type,
                                             void *istream, void *ostream);

#endif /* __EL2GO_KEYSTORE_H__ */
