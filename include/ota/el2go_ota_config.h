/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef __EL2GO_OTA_CONFIG_H__
#define __EL2GO_OTA_CONFIG_H__

#include <stddef.h>
#include <stdint.h>

/**
 * @brief mTLS configuration for the EL2GO OTA server connection.
 *
 * All pointer fields must remain valid for the lifetime of the context
 * (until el2go_ota_cleanup() is called).
 */
typedef struct {
    const char *hostname;           /**< OTA server hostname or IP address. Must not be NULL. */
    uint16_t port;                  /**< OTA server port (e.g. 443 for HTTPS/gRPC-TLS). */
    const uint8_t *server_ca_chain; /**< DER-encoded server CA certificate chain.
                                     *   Root CA, or Root CA + Intermediate CA concatenated.
                                     *   Must not be NULL. */
    size_t server_ca_chain_size;    /**< Size of server_ca_chain in bytes. Must be > 0. */
    uint32_t client_key_object_id;  /**< Object ID of the provisioned client private key. */
    uint32_t client_cert_object_id; /**< Object ID of the provisioned client X.509 certificate
                                     *   (DER-encoded). */
} el2go_ota_mtls_config_t;

#endif /* __EL2GO_OTA_CONFIG_H__ */
