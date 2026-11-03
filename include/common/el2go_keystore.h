/*
 * Copyright 2018-2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef __EL2GO_KEYSTORE_H__
#define __EL2GO_KEYSTORE_H__

#include <stdint.h>
#include <stddef.h>
#include "common/el2go_status.h"

/**
 * @defgroup el2go_keystore Keystore Public API
 * @brief Keystore abstraction interface for EdgeLock 2GO.
 * @{
 */

/**
 * @brief Platform context.
 *
 * Opaque platform context used to access hardware and HSM resources.
 * See @ref el2go_platform_ctx_t for the full type documentation.
 */
typedef struct el2go_platform_ctx el2go_platform_ctx_t;

/**
 * @brief Keystore backend type.
 */
typedef enum {
    EL2GO_KEYSTORE_SSS, /**< SSS (Secure Subsystem) keystore */
    EL2GO_KEYSTORE_PSA  /**< PSA (Platform Security Architecture) keystore */
} el2go_keystore_type_t;

/**
 * @brief IoT Agent keystore instance.
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
    uint32_t id;                        /**< Keystore identifier */
    el2go_keystore_type_t type;         /**< Keystore type (SSS or PSA) */
    void *context;                      /**< Keystore context */
    void *priv;                         /**< Private data */
    el2go_platform_ctx_t *platform_ctx; /**< Platform context */
} el2go_keystore_t;

/**
 * @brief Initialize a keystore.
 *
 * Initializes a keystore with the specified identifier and platform context.
 *
 * @param[in]  id           Keystore identifier.
 * @param[in]  platform_ctx Platform context for hardware access.
 * @param[out] keystore     Pointer to the keystore structure to initialize.
 *
 * @return EL2GO_STATUS_SUCCESS on success, error code otherwise.
 */
el2go_status_t el2go_keystore_init(uint32_t id, el2go_platform_ctx_t *platform_ctx,
                                   el2go_keystore_t *keystore);

/**
 * @brief Free a keystore.
 *
 * Frees all resources associated with the keystore.
 *
 * @param[in] keystore Pointer to the keystore structure to free.
 *
 * @return EL2GO_STATUS_SUCCESS on success, error code otherwise.
 */
el2go_status_t el2go_keystore_free(el2go_keystore_t *keystore);

/**
 * @brief Open a session with the keystore.
 *
 * Opens a session with the underlying secure element or keystore backend.
 * A session must be opened before performing cryptographic operations.
 * For PSA keystores, this may initialize the crypto subsystem.
 * For SSS keystores, this establishes communication with the secure element.
 *
 * @param[in] keystore Pointer to the keystore structure.
 *
 * @return EL2GO_STATUS_SUCCESS on success, error code otherwise.
 */
el2go_status_t el2go_keystore_open_session(el2go_keystore_t *keystore);

/**
 * @brief Close a session with the keystore.
 *
 * Closes an active session with the keystore. All pending operations should
 * be completed before closing the session. After closing, a new session must
 * be opened to perform additional operations.
 *
 * @param[in] keystore Pointer to the keystore structure.
 *
 * @return EL2GO_STATUS_SUCCESS on success, error code otherwise.
 */
el2go_status_t el2go_keystore_close_session(el2go_keystore_t *keystore);

/**
 * @brief Import a claim code for device provisioning.
 *
 * Stores the claim code for device provisioning. The PSA keystore
 * implementation first delegates to the platform layer; if no platform
 * override is present it uses a generic PSA ITS fallback. Non-PSA keystores
 * may provide their own override or rely on the default no-op stub.
 *
 * @param[in] keystore      Initialized keystore.
 * @param[in] claimcode     Claim code string (not necessarily null-terminated).
 * @param[in] claimcode_len Length of the claim code in bytes.
 *
 * @return EL2GO_STATUS_SUCCESS on success, error code otherwise.
 */
el2go_status_t el2go_keystore_import_claimcode(el2go_keystore_t *keystore, const char *claimcode,
                                               size_t claimcode_len);

/**
 * @brief Import claimcode blob from a fixed flash address into PSA ITS.
 *
 * Reads the claimcode blob from EL2GO_RTP_CLAIMCODE_FLASH_ADDRESS,
 * validates the magic indicator {'E','2','G','C'}, and writes it into PSA ITS
 * under EDGELOCK2GO_CLAIMCODE_DATA_ID. No-op if already stored.
 *
 * A weak no-op default is provided in el2go_keystore.c; the real PSA
 * implementation in libs/keystores/psa/ overrides it when linked.
 *
 * @param[in] keystore  Initialized keystore (used for context only).
 *
 * @retval EL2GO_STATUS_SUCCESS on success or if already stored.
 * @retval EL2GO_STATUS_INVALID_PARAMETER if the magic bytes do not match.
 * @retval EL2GO_STATUS_PSA_ERROR on PSA ITS write failure.
 */
el2go_status_t el2go_keystore_import_claimcode_from_flash(el2go_keystore_t *keystore);

/** @} */ /* end of el2go_keystore */

#endif /* __EL2GO_KEYSTORE_H__ */
