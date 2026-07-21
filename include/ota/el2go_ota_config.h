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
 * @brief Maximum number of bytes requested per chunk from the OTA server.
 *
 * Tune this value to match the available stack budget on the target platform.
 * On Zephyr it is set via CONFIG_EL2GO_OTA_CHUNK_SIZE in Kconfig.
 * On other platforms define EL2GO_OTA_CHUNK_SIZE in the build system before
 * including this header to override the default.
 *
 * Default: 4096 bytes.
 */
#ifndef EL2GO_OTA_CHUNK_SIZE
#ifdef CONFIG_EL2GO_OTA_CHUNK_SIZE
#define EL2GO_OTA_CHUNK_SIZE CONFIG_EL2GO_OTA_CHUNK_SIZE
#else
#define EL2GO_OTA_CHUNK_SIZE 4096U
#endif
#endif /* EL2GO_OTA_CHUNK_SIZE */

/**
 * @brief Extra bytes reserved in the wire buffer for gRPC/protobuf framing overhead.
 *
 * Covers the 5-byte gRPC frame header, protobuf field tags and length prefixes,
 * and HTTP/2 HEADERS framing. The actual overhead for the current proto schema
 * is well under 100 bytes; 256 provides a conservative margin.
 * Override in the build system if a tighter budget is required.
 *
 * Default: 256 bytes.
 */
#ifndef EL2GO_OTA_WIRE_OVERHEAD
#define EL2GO_OTA_WIRE_OVERHEAD 256U
#endif /* EL2GO_OTA_WIRE_OVERHEAD */

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
