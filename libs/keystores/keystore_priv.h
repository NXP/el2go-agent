/*
 * Copyright 2018-2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef __KEYSTORE_PRIV_H__
#define __KEYSTORE_PRIV_H__

#include "common/el2go_keystore.h"

/**
 * @defgroup el2go_keystore_int Keystore Internal API
 * @brief Keystore interface for internal module use.
 * @{
 */

/**
 * @brief Handle a keystore request
 *
 * Processes incoming keystore requests by decoding the request, executing
 * the appropriate command, and encoding the response.
 *
 * @param[in]  keystore      Pointer to keystore structure.
 * @param[in]  message_type  Message type fields.
 * @param[in]  istream       Input stream with request data.
 * @param[out] ostream       Output stream for response data.
 *
 * @return @ref el2go_status_t value, @ref EL2GO_STATUS_SUCCESS on success.
 */
el2go_status_t el2go_keystore_handle_request(el2go_keystore_t *keystore, const void *message_type,
                                             void *istream, void *ostream);

/** @} */ /* end of el2go_keystore_int */

#endif /* __KEYSTORE_PRIV_H__ */
