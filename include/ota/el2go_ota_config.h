/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef __EL2GO_OTA_CONFIG_H__
#define __EL2GO_OTA_CONFIG_H__

/** @defgroup el2go_ota_config OTA Configuration
 * @brief Compile-time tunables and TLS configuration types for the EL2GO OTA library.
 * @{
 */

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
 * Upper bounds on this value (largest first):
 *   - gRPC message size: the OTA server enforces the standard gRPC default
 *     max message size of 4 MiB (see FetchFile in ota-delivery.proto). A
 *     chunk request/response larger than this is rejected by the server.
 *   - HTTP/2 frame size: the gRPC/HTTP2 transport backend (el2go_ota_grpc.c)
 *     reassembles a received gRPC message that the server -- or a proxy such
 *     as Envoy -- split across several DATA frames, at any byte boundary of
 *     the 5-byte message prefix or of the body. It does NOT split an
 *     outgoing message: grpc_send() writes each request as a single DATA
 *     frame, which must fit the peer's SETTINGS_MAX_FRAME_SIZE (default
 *     16384 bytes, RFC 7540 S6.5.2). As a conservative guard,
 *     (EL2GO_OTA_CHUNK_SIZE + EL2GO_OTA_WIRE_OVERHEAD) is kept at or below
 *     that default so a message normally travels in one frame. See the
 *     compile-time guard in el2go_ota_download_engine.c.
 *   - Stack budget: the wire buffer sized off this value is stack-allocated
 *     in el2go_ota_download_engine.c (not heap). Raising this value grows
 *     the stack usage of whatever RTOS thread calls into the download
 *     engine -- check the target's configured thread/task stack size
 *     (e.g. Zephyr CONFIG_MAIN_STACK_SIZE or the calling thread's stack)
 *     before increasing the default.
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
 * See the EL2GO_OTA_CHUNK_SIZE documentation above for the upper bounds that
 * apply to (EL2GO_OTA_CHUNK_SIZE + EL2GO_OTA_WIRE_OVERHEAD) as a whole.
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

/** @} */ /* end of el2go_ota_config */

#endif /* __EL2GO_OTA_CONFIG_H__ */
