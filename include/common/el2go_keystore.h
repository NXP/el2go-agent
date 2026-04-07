/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright 2018-2026 NXP
 */

#ifndef __EL2GO_KEYSTORE_H__
#define __EL2GO_KEYSTORE_H__

#include <stdint.h>
#include "common/el2go_status.h"

typedef struct el2go_agent_platform_ctx el2go_agent_platform_ctx_t;

/*
* Keystore types
*/
/* clang-format off */
typedef enum {
	EL2GO_AGENT_KEYSTORE_SSS, /* SSS (Secure Subsystem) keystore */
	EL2GO_AGENT_KEYSTORE_PSA /* PSA (Platform Security Architecture) keystore */
} el2go_agent_keystore_type_t;
/* clang-format on */

/**
 * IoT Agent keystore
 *
 * This structure contains fields used to manage keystores. Some fields are
 * used by the keystore implementations (context) and others are used for
 * managing the keystores by the agent. Some of them are public fields
 * (like id, type) and some of them are private (priv).
 *
 * Users should only access and modify the public fields and the context field
 * for keystore implementations. The priv field is for internal agent
 * use only and must not be accessed or modified by users.
 */
/* clang-format off */
typedef struct el2go_agent_keystore {
			uint32_t id;                              /* Keystore identifier */
			el2go_agent_keystore_type_t type;         /* Keystore type */
			void *context;                            /* Keystore context */
			void *priv;                               /* Private agent data */
} el2go_agent_keystore_t;
/* clang-format on */

/**
 * el2go_agent_keystore_init - Initialize a keystore
 * @id: Keystore identifier
 * @type: Keystore type (SSS or PSA)
 * @platform_ctx: Platform context for hardware access
 * @keystore: Pointer to keystore structure
 *
 * This function initializes a keystore with the specified platform
 * and type.
 *
 * Return:
 * EL2GO_AGENT_SUCCESS on success, error code otherwise
 */
el2go_agent_t
el2go_agent_keystore_init(uint32_t id, el2go_agent_keystore_type_t type,
			  el2go_agent_platform_ctx_t *platform_ctx,
			  el2go_agent_keystore_t *keystore);

/**
* el2go_agent_keystore_free - Free a keystore
* @keystore: Pointer to keystore structure
*
* This function frees all resources associated with the keystore.
*
* Return:
* EL2GO_AGENT_SUCCESS on success, error code otherwise
*/
el2go_agent_t el2go_agent_keystore_free(el2go_agent_keystore_t *keystore);

/**
* el2go_agent_keystore_open_session - Open a session with the keystore
* @keystore: Keystore structure
*
* This function opens a session with the underlying secure element or
* keystore backend. A session must be opened before performing cryptographic
* operations. For PSA keystores, this may initialize the crypto subsystem.
* For SSS keystores, this establishes communication with the secure element.
*
* Return:
* EL2GO_AGENT_SUCCESS on success, error code otherwise
*/
el2go_agent_t
el2go_agent_keystore_open_session(el2go_agent_keystore_t *keystore);

/**
* el2go_agent_keystore_close_session - Close a session with the keystore
* @keystore: Keystore structure
*
* This function closes an active session with the keystore. All pending
* operations should be completed before closing the session. After closing,
* a new session must be opened to perform additional operations.
*
* Return:
* EL2GO_AGENT_SUCCESS on success, error code otherwise
*/
el2go_agent_t
el2go_agent_keystore_close_session(el2go_agent_keystore_t *keystore);

#endif /* __EL2GO_KEYSTORE_H__ */
