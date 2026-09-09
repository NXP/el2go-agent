/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef __EL2GO_OTA_CRED_H__
#define __EL2GO_OTA_CRED_H__

/** @defgroup el2go_ota_cred OTA Credential Provider Internal API
 * @brief Internal API for acquiring client TLS credentials for the OTA library.
 * @{
 */

#include <stdint.h>
#include <stddef.h>

#include "common/el2go_status.h"
#include "common/el2go_platform.h"
#include "ota/el2go_ota_config.h"

/**
 * @brief Acquire the client certificate and private key ID for mTLS.
 *
 * Called once during el2go_ota_tls_init(). The implementation is
 * determined at build time by EL2GO_OTA_CRED_PROVIDER.
 *
 * On success the function allocates *cert_der. The caller is responsible
 * for freeing it with osal_free() after it has been passed to
 * net_crypto_set_cli_cert().
 *
 * @param[in]  platform_ctx   Initialised platform context. Must not be NULL.
 * @param[in]  config         OTA library config. Must not be NULL.
 *                            Uses config->client_cert_object_id to locate the
 *                            DER certificate in PSA ITS, and
 *                            config->client_key_object_id as the private key reference.
 * @param[out] cert_der       Receives pointer to allocated DER-encoded
 *                            client certificate buffer.
 * @param[out] cert_der_len   Receives length of *cert_der in bytes.
 * @param[out] key_id         Receives the key ID to pass to
 *                            net_crypto_associate_key().
 *
 * @retval EL2GO_STATUS_SUCCESS on success.
 * @retval EL2GO_STATUS_ALLOCATION_ERROR if a heap allocation fails.
 * @retval EL2GO_STATUS_NET_CRYPTO_INVALID_CERT if certificate
 *          retrieval from PSA ITS fails.
 * @retval EL2GO_STATUS_NET_CRYPTO_INVALID_KEY if the key cannot
 *          be accessed from the PSA keystore.
 */
el2go_status_t el2go_ota_prepare_client_credentials(el2go_platform_ctx_t *platform_ctx,
                                                    const el2go_ota_mtls_config_t *config,
                                                    uint8_t **cert_der, size_t *cert_der_len,
                                                    uint32_t *key_id);

/** @} */ /* end of el2go_ota_cred */

#endif /* __EL2GO_OTA_CRED_H__ */
