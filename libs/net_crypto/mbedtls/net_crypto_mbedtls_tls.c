/*
 * Copyright 2018-2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

/*
 * TLS/connection subset of the mbedTLS net_crypto backend.
 *
 * Contains: SSL/TLS context management, TCP connection setup,
 *           TLS handshake, certificate and key configuration,
 *           cipher suite / curve selection, ALPN, and
 *           CRL-based certificate verification.
 *
 * This file requires a POSIX-compatible networking stack
 * (mbedtls/net_sockets.h) and is therefore compiled only when
 * CONFIG_NETWORKING is set (Zephyr) or on hosted platforms (Linux).
 *
 * Pure crypto operations (SHA, CSR, cert parsing) live in
 * net_crypto_mbedtls_crypto.c and are always compiled.
 */

#include <string.h>
#include <stdlib.h>

#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/pk.h>
#include <mbedtls/error.h>
#include <mbedtls/debug.h>

#include "builtin_macros.h"
#include "osal.h"
#include "compiler.h"
#include "debug.h"

#include "net_crypto.h"
#include "mbedtls_debug.h"

#include "mapping/mbedtls_mapping.h"
#include "tls/mbedtls_compat_tls.h"
#include "crypto/mbedtls_compat_crypto.h"

/** Maximum length for port number string representation */
#define NET_CRYPTO_PORT_STR_LEN 16

/** Read timeout in milliseconds for a single SSL read call.
 * select() blocks for at most this duration waiting for data from the server.
 * A clean link drop (RST/FIN) is detected immediately regardless of this value.
 * Override at cmake configure time with -DNET_CRYPTO_SSL_READ_TIMEOUT_MS=<ms>. */
#ifndef NET_CRYPTO_SSL_READ_TIMEOUT_MS
#define NET_CRYPTO_SSL_READ_TIMEOUT_MS 60000U
#endif

/**
 * @brief Network crypto context structure
 *
 * Contains all mbedTLS contexts and configuration needed for secure
 * network communication.
 */
struct net_crypto_ctx {
    mbedtls_net_context net_ctx;         /**< Network socket context */
    mbedtls_ssl_context ssl;             /**< SSL/TLS context */
    mbedtls_ssl_config conf;             /**< SSL/TLS configuration */
    mbedtls_compat_rng_context *rng_ctx; /**< Random number generator context */
    mbedtls_x509_crt ca_cert;            /**< CA certificate chain */
    mbedtls_x509_crt cli_cert;           /**< Client certificate */
    mbedtls_pk_context pkey;             /**< Private key context */
    char *hostname;                      /**< Server hostname */
    uint16_t port;                       /**< Server port number */
    bool configured;                     /**< Configuration status flag */
    bool connected;                      /**< Connection status flag */
    bool ca_cert_set;                    /**< CA certificate set flag */
    bool cli_cert_set;                   /**< Client certificate set flag */
    bool alpn_set;                       /**< ALPN protocol list configured flag */
    int *ciphers; /**< Cipher suites array (allocated by net_crypto_set_cipher_suites, freed in net_crypto_free) */
    void *curves; /**< Elliptic curves array (allocated by net_crypto_set_curves, freed in net_crypto_free) */
};

/**
 * @brief Configure max TLS fragment length based on available memory
 *
 * Configures the TLS Max Fragment Length extension (RFC 6066) to prevent the server
 * from sending TLS records larger than our buffer can handle on memory-constrained devices.
 *
 * @param[in,out] conf SSL configuration context
 *
 * @return EL2GO_STATUS_SUCCESS on success, error code otherwise.
 */
static el2go_status_t configure_max_fragment_len(mbedtls_ssl_config *conf)
{
    int ret = 0;
    unsigned char max_fragment_len = MBEDTLS_SSL_MAX_FRAG_LEN_NONE;
    unsigned int max_content_len = 0U;

    if (!TO_UNSIGNED(MBEDTLS_SSL_MAX_CONTENT_LEN, max_content_len)) {
        if (max_content_len < MBEDTLS_COMPAT_FRAG_LEN_2048)
            max_fragment_len = MBEDTLS_SSL_MAX_FRAG_LEN_2048;
        else if (max_content_len < MBEDTLS_COMPAT_FRAG_LEN_4096)
            max_fragment_len = MBEDTLS_SSL_MAX_FRAG_LEN_4096;
    }

    if (max_fragment_len == MBEDTLS_SSL_MAX_FRAG_LEN_NONE)
        return EL2GO_STATUS_SUCCESS;

    EL2GO_DBG_PRINTF(VERBOSE, "Setting max fragment length\n");
    ret = mbedtls_ssl_conf_max_frag_len(conf, max_fragment_len);
    if (ret != 0) {
        EL2GO_DBG_PRINTF(ERROR, "Set fragment failed -0x%04x\n", -ret);
        return EL2GO_STATUS_NET_CRYPTO_SSL_CONFIG_FAILED;
    }

    return EL2GO_STATUS_SUCCESS;
}

/**
 * @brief Warn about certificate/CRL validity period issues
 *
 * Logs a warning if the certificate or CRL are outside their validity period,
 * which may indicate the device time is incorrectly set.
 *
 * @param[in] verify_result Verification result flags from mbedTLS
 */
static void warn_crt_crl_period(uint32_t verify_result)
{
    if ((verify_result & MBEDTLS_X509_BADCRL_EXPIRED) ||
        (verify_result & MBEDTLS_X509_BADCRL_FUTURE) ||
        (verify_result & MBEDTLS_X509_BADCERT_EXPIRED) ||
        (verify_result & MBEDTLS_X509_BADCERT_FUTURE)) {
        EL2GO_DBG_PRINTF(INFO, "The certificate and/or CRL are outside their validity period.\n");
        EL2GO_DBG_PRINTF(INFO, "The device time may be wrong.\n");
        EL2GO_DBG_PRINTF(INFO, "Please make sure that the time is correctly set.\n");
    }
}

/**
 * @brief Handle SSL handshake verification failure
 *
 * @param[in] ctx Network crypto context
 * @param[in] ret mbedTLS error code
 *
 * @return Appropriate el2go_status_t error code.
 */
static el2go_status_t handle_handshake_failure(net_crypto_ctx_t *ctx, int ret)
{
    el2go_status_t status = EL2GO_STATUS_NET_CRYPTO_HANDSHAKE_FAILED;
    uint32_t verify_result = 0;

    if (ret == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED) {
        verify_result = mbedtls_ssl_get_verify_result(&ctx->ssl);
        EL2GO_DBG_PRINTF(ERROR, "Certificate verification failed: 0x%08x\n", verify_result);
        warn_crt_crl_period(verify_result);
        status = EL2GO_STATUS_NET_CRYPTO_CERT_VERIFY_FAILED;
    } else {
        el2go_dbg_mbedtls_err(ret);
    }

    return status;
}

/**
 * @brief Filter cipher suites in-place to match the configured key bit length.
 *
 * When a private key is associated this helper ensures that only suites
 * whose hash algorithm matches the key size are offered to the server:
 *   - 256-bit keys: keep only suites whose name contains "SHA256"
 *   - 384-bit keys: keep only suites whose name contains "SHA384"
 *   - other sizes:  no filtering applied
 *
 * If no explicit cipher list has been set (ctx->ciphers == NULL) the
 * platform list is fetched via el2go_platform_get_cipher_suites(), allocated,
 * and stored in ctx->ciphers before filtering.  Ownership stays with the
 * context and the buffer is freed in net_crypto_free().
 *
 * The filtered list is re-applied to the SSL configuration so that the server
 * cannot negotiate a cipher suite requiring a hash the key does not support.
 *
 * @param[in,out] ctx  Network crypto context.
 */
static void filter_ciphers_by_key_bitlen(net_crypto_ctx_t *ctx)
{
    size_t key_bitlen = 0;
    const char *sha_tag = NULL;
    int *read_ptr = NULL;
    int *write_ptr = NULL;
    const char *name = NULL;
    el2go_cipher_list_t plat_list;
    size_t max_ciphers = 0;
    int num_ciphers = 0;

    if (!mbedtls_compat_pk_has_key(&ctx->pkey))
        return;

    /* Derive bit-length from the client certificate public key when available,
     * because mbedtls_pk_get_bitlen() returns 0 for hardware-backed opaque keys.
     * The certificate's public key is always correctly populated after parsing. */
    if (ctx->cli_cert_set)
        key_bitlen = mbedtls_pk_get_bitlen(&ctx->cli_cert.pk);
    else
        key_bitlen = mbedtls_pk_get_bitlen(&ctx->pkey);

    if (key_bitlen == 256U)
        sha_tag = "SHA256";
    else if (key_bitlen == 384U)
        sha_tag = "SHA384";
    else
        return;

    /* If no explicit cipher list was configured, build one from the platform
     * defaults so that the filter has something to work with. */
    if (ctx->ciphers == NULL) {
        plat_list = el2go_platform_get_cipher_suites();
        if (plat_list.count == 0) {
            EL2GO_DBG_PRINTF(VERBOSE, "Platform cipher list empty, skipping filter\n");
            return;
        }

        if (ADD_OVERFLOW(plat_list.count, 1, &max_ciphers)) {
            EL2GO_DBG_PRINTF(ERROR, "Cipher suite count overflow, skipping filter\n");
            return;
        }

        ctx->ciphers = osal_calloc(max_ciphers, sizeof(int));
        if (!ctx->ciphers) {
            EL2GO_DBG_PRINTF(ERROR, "Failed to allocate cipher suite array for filter\n");
            return;
        }

        num_ciphers = cipher_list_to_mbedtls(&plat_list, ctx->ciphers, max_ciphers);
        if (num_ciphers <= 0) {
            EL2GO_DBG_PRINTF(ERROR, "cipher_list_to_mbedtls failed (%d), skipping filter\n",
                             num_ciphers);
            osal_free(ctx->ciphers);
            ctx->ciphers = NULL;
            return;
        }
    }

    EL2GO_DBG_PRINTF(VERBOSE, "Filtering cipher suites for %zu-bit key (keeping %s only)\n",
                     key_bitlen, sha_tag);

    read_ptr = ctx->ciphers;
    write_ptr = ctx->ciphers;

    while (*read_ptr != 0) {
        name = mbedtls_ssl_get_ciphersuite_name(*read_ptr);
        if (name != NULL && strstr(name, sha_tag) != NULL) {
            *write_ptr = *read_ptr;
            write_ptr++;
        }
        read_ptr++;
    }
    *write_ptr = 0;

    mbedtls_ssl_conf_ciphersuites(&ctx->conf, ctx->ciphers);
}

el2go_status_t net_crypto_new(net_crypto_ctx_t **ctx)
{
    net_crypto_ctx_t *new_ctx = NULL;
    el2go_status_t status = EL2GO_STATUS_SUCCESS;

    EL2GO_DBG_TRACE_FUNCTION_CALL;

    if (!ctx) {
        status = EL2GO_STATUS_INVALID_PARAMETER;
        goto exit;
    }

    new_ctx = osal_calloc(1, sizeof(net_crypto_ctx_t));
    if (!new_ctx) {
        status = EL2GO_STATUS_ALLOCATION_ERROR;
        goto exit;
    }

    *ctx = new_ctx;

exit:
    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}

el2go_status_t net_crypto_set_cli_cert(net_crypto_ctx_t *ctx, const uint8_t *cert_pem,
                                       size_t cert_len)
{
    int ret = 0;
    el2go_status_t status = EL2GO_STATUS_SUCCESS;

    EL2GO_DBG_TRACE_FUNCTION_CALL;

    if (!ctx || !cert_pem)
        return EL2GO_STATUS_INVALID_PARAMETER;

    /* Mark that client certificate is not set until successful parsing */
    ctx->cli_cert_set = false;

    /* Initialize the certificate structure if not already done */
    mbedtls_x509_crt_init(&ctx->cli_cert);

    ret = mbedtls_x509_crt_parse_der(&ctx->cli_cert, cert_pem, cert_len);
    if (ret != 0) {
        EL2GO_DBG_PRINTF(ERROR, "Client certificate parsing failed: -0x%04x\n", -ret);
        status = EL2GO_STATUS_NET_CRYPTO_INVALID_CERT;
        goto exit;
    }
    ctx->cli_cert_set = true;

exit:
    if (status != EL2GO_STATUS_SUCCESS)
        mbedtls_x509_crt_free(&ctx->cli_cert);

    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}

el2go_status_t net_crypto_set_server_cert(net_crypto_ctx_t *ctx, const uint8_t *ca_cert_pem,
                                          size_t ca_cert_len)
{
    int ret = 0;
    const uint8_t *pos = NULL;
    const uint8_t *end_ptr = NULL;
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    const uint8_t *start = NULL;
    size_t len = 0U;
    size_t cert_size = 0U;
    int tag = 0;

    EL2GO_DBG_TRACE_FUNCTION_CALL;

    if (!ctx || !ca_cert_pem)
        return EL2GO_STATUS_INVALID_PARAMETER;

    /* Mark that CA certificate is not set until successful parsing */
    ctx->ca_cert_set = false;

    /* Initialize the CA certificate chain structure */
    mbedtls_x509_crt_init(&ctx->ca_cert);

    pos = ca_cert_pem;
    end_ptr = pos + ca_cert_len;

    /* Parse multiple certificates in the chain */
    while (pos < end_ptr) {
        /* We expect the certificate to start with a sequence tag,
         * from that we get the length so we can jump to the next
         * one in the buffer.
         */
        start = pos;
        tag = MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE;

        ret = mbedtls_asn1_get_tag((unsigned char **)&pos, end_ptr, &len, tag);
        if (ret != 0) {
            EL2GO_DBG_PRINTF(ERROR, "mbedtls_asn1_get_tag err: -0x%04x\n", -ret);
            status = EL2GO_STATUS_NET_CRYPTO_INVALID_CERT;
            goto exit;
        }

        pos += len;

        if ((end_ptr - start) < 0) {
            EL2GO_DBG_PRINTF(ERROR, "Error in parsing CA certificate\n");
            status = EL2GO_STATUS_NET_CRYPTO_INVALID_CERT;
            goto exit;
        }

        /* Calculate the size of this individual certificate */
        cert_size = pos - start;

        /* Parse this certificate and add it to the chain */
        ret = mbedtls_x509_crt_parse_der(&ctx->ca_cert, start, cert_size);
        if (ret != 0) {
            EL2GO_DBG_PRINTF(ERROR, "Parse server cert failed: -0x%04x\n", -ret);
            status = EL2GO_STATUS_NET_CRYPTO_INVALID_CERT;
            goto exit;
        }
    }

    /* Mark that CA certificate has been successfully set */
    ctx->ca_cert_set = true;

exit:
    if (status != EL2GO_STATUS_SUCCESS)
        mbedtls_x509_crt_free(&ctx->ca_cert);

    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}

el2go_status_t net_crypto_set_cipher_suites(net_crypto_ctx_t *ctx,
                                            const el2go_cipher_list_t *cipher_suites)
{
    int *mbedtls_ciphers = NULL;
    size_t max_ciphers = 0;
    int num_ciphers = 0;
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    const char __maybe_unused *name = NULL;

    EL2GO_DBG_TRACE_FUNCTION_CALL;

    if (!ctx)
        return EL2GO_STATUS_INVALID_PARAMETER;

    if (!ctx->configured) {
        EL2GO_DBG_PRINTF(ERROR, "Set cipher suites: context not configured\n");
        return EL2GO_STATUS_INVALID_PARAMETER;
    }

    /* Check if cipher suites are provided */
    if (!cipher_suites || !cipher_suites->suites || cipher_suites->count == 0) {
        EL2GO_DBG_PRINTF(VERBOSE, "Use mbedTLS default cipher suites\n");
        return EL2GO_STATUS_SUCCESS;
    }

    /* Free previously allocated ciphers if any */
    if (ctx->ciphers) {
        osal_free(ctx->ciphers);
        ctx->ciphers = NULL;
    }

    if (ADD_OVERFLOW(cipher_suites->count, 1, &max_ciphers)) {
        EL2GO_DBG_PRINTF(ERROR, "cipher_suites->count (%zu) too large\n", cipher_suites->count);
        return EL2GO_STATUS_INVALID_PARAMETER;
    }

    /* Allocate array based on actual cipher suite count + 1 for terminator */
    mbedtls_ciphers = osal_calloc(max_ciphers, sizeof(int));
    if (!mbedtls_ciphers) {
        EL2GO_DBG_PRINTF(ERROR, "Failed to allocate cipher suite array\n");
        return EL2GO_STATUS_ALLOCATION_ERROR;
    }

    /* Convert platform cipher suites to mbedTLS format */
    num_ciphers = cipher_list_to_mbedtls(cipher_suites, mbedtls_ciphers, max_ciphers);
    if (num_ciphers < 0) {
        EL2GO_DBG_PRINTF(ERROR, "Failed to convert cipher suites\n");
        status = EL2GO_STATUS_NET_CRYPTO_CONFIG_FAILED;
        goto exit;
    }

    if (num_ciphers == 0) {
        EL2GO_DBG_PRINTF(VERBOSE, "No compatible cipher suites found\n");
        EL2GO_DBG_PRINTF(VERBOSE, "Use mbedTLS default cipher suites\n");
        osal_free(mbedtls_ciphers);
        ctx->ciphers = NULL;
        goto exit;
    }

    /* Configure cipher suites - mbedTLS stores pointer, does NOT copy */
    mbedtls_ssl_conf_ciphersuites(&ctx->conf, mbedtls_ciphers);

    /* Transfer ownership to context - freed in net_crypto_free() */
    ctx->ciphers = mbedtls_ciphers;

    EL2GO_DBG_PRINTF(VERBOSE, "Configured %d cipher suites\n", num_ciphers);

    /* Debug: print configured cipher suites */
    for (int i = 0; i < num_ciphers; i++) {
        name = mbedtls_ssl_get_ciphersuite_name(mbedtls_ciphers[i]);
        EL2GO_DBG_PRINTF(VERBOSE, "  [%d] 0x%04x - %s\n", i, mbedtls_ciphers[i],
                         name ? name : "unknown");
    }

exit:
    /* Free temporary buffer if ownership was not transferred to context */
    if (status != EL2GO_STATUS_SUCCESS && mbedtls_ciphers)
        osal_free(mbedtls_ciphers);

    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}

el2go_status_t net_crypto_configure(net_crypto_ctx_t *ctx, const net_crypto_config_t *config)
{
    int ret = 0;
    const char *pers = "el2go_net_crypto";
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    size_t hostname_len = 0;

    EL2GO_DBG_TRACE_FUNCTION_CALL;

    if (!ctx || !config)
        return EL2GO_STATUS_INVALID_PARAMETER;

    if (!config->hostname)
        return EL2GO_STATUS_INVALID_PARAMETER;

    /* Check if already configured - prevent double configuration */
    if (ctx->configured) {
        EL2GO_DBG_PRINTF(ERROR, "Context already configured\n");
        return EL2GO_STATUS_INVALID_PARAMETER;
    }

    ctx->configured = false;

    /* Initialize mbedTLS structures */
    mbedtls_ssl_init(&ctx->ssl);
    mbedtls_ssl_config_init(&ctx->conf);

#ifdef EL2GO_MBEDTLS_DEBUG_ENABLE
    /* Enable mbedTLS debug output */
    mbedtls_ssl_conf_dbg(&ctx->conf, mbedtls_debug_cb, NULL);
    mbedtls_debug_set_threshold(4);
#endif

    /* Initialize RNG using compatibility layer */
    ret = mbedtls_compat_rng_init(&ctx->rng_ctx, (const unsigned char *)pers, strlen(pers));
    if (ret != 0) {
        EL2GO_DBG_PRINTF(ERROR, "Failed to init RNG: -0x%04x\n", -ret);
        status = EL2GO_STATUS_NET_CRYPTO_CONFIG_FAILED;
        goto exit;
    }

    /* Configure SSL/TLS defaults */
    ret = mbedtls_ssl_config_defaults(&ctx->conf, MBEDTLS_SSL_IS_CLIENT,
                                      MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) {
        EL2GO_DBG_PRINTF(ERROR, "SSL config defaults failed: -0x%04x\n", -ret);
        status = EL2GO_STATUS_NET_CRYPTO_CONFIG_FAILED;
        goto exit;
    }

    if (ADD_OVERFLOW(strlen(config->hostname), 1, &hostname_len)) {
        status = EL2GO_STATUS_ARITHMETIC_OVERFLOW;
        goto exit;
    }

    ctx->hostname = osal_calloc(1, hostname_len);
    if (!ctx->hostname) {
        status = EL2GO_STATUS_ALLOCATION_ERROR;
        goto exit;
    }
    (void)memcpy(ctx->hostname, config->hostname, hostname_len - 1);

    ctx->port = config->port;
    ctx->configured = true;

exit:
    if (status != EL2GO_STATUS_SUCCESS) {
        /* Free all initialized mbedTLS structures on error */
        mbedtls_ssl_free(&ctx->ssl);
        mbedtls_ssl_config_free(&ctx->conf);
        mbedtls_compat_rng_free(ctx->rng_ctx);
        ctx->rng_ctx = NULL;

        /* Free hostname if allocated */
        if (ctx->hostname) {
            osal_free(ctx->hostname);
            ctx->hostname = NULL;
        }
    }
    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}

el2go_status_t net_crypto_associate_key(net_crypto_ctx_t *ctx, uint32_t object_id)
{
    int ret = 0;
    el2go_status_t status = EL2GO_STATUS_SUCCESS;

    EL2GO_DBG_TRACE_FUNCTION_CALL;

    if (!ctx)
        return EL2GO_STATUS_INVALID_PARAMETER;

    /* Initialize the private key context if not already done */
    mbedtls_pk_init(&ctx->pkey);

    /* Setup opaque key reference using compatibility layer */
    ret = mbedtls_compat_pk_setup_key(&ctx->pkey, object_id);
    if (ret != 0) {
        EL2GO_DBG_PRINTF(ERROR, "pk_setup_key failed -0x%04x\n", -ret);
        status = EL2GO_STATUS_NET_CRYPTO_INVALID_KEY;
        goto exit;
    }

exit:
    if (status != EL2GO_STATUS_SUCCESS)
        mbedtls_pk_free(&ctx->pkey);

    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}

el2go_status_t net_crypto_connect(net_crypto_ctx_t *ctx)
{
    int ret = 0;
    char port_str[NET_CRYPTO_PORT_STR_LEN] = { 0 };
    el2go_status_t status = EL2GO_STATUS_SUCCESS;

    EL2GO_DBG_TRACE_FUNCTION_CALL;

    if (!ctx || !ctx->configured)
        return EL2GO_STATUS_INVALID_PARAMETER;

    if (ctx->connected)
        return EL2GO_STATUS_SUCCESS;

    EL2GO_DBG_PRINTF(VERBOSE, "Connecting to %s:%u\n", ctx->hostname, ctx->port);

    /* Convert port to string */
    ret = osal_snprintf(port_str, sizeof(port_str), "%u", ctx->port);
    if (ret < 0 || ret >= (int)sizeof(port_str)) {
        EL2GO_DBG_PRINTF(ERROR, "Failed to format port number\n");
        return EL2GO_STATUS_INVALID_PARAMETER;
    }

    /* Establish TCP connection */
    mbedtls_net_init(&ctx->net_ctx);

    EL2GO_DBG_PRINTF(VERBOSE, "Establishing TCP connection to %s:%s\n", ctx->hostname, port_str);
    ret = mbedtls_net_connect(&ctx->net_ctx, ctx->hostname, port_str, MBEDTLS_NET_PROTO_TCP);
    if (ret != 0) {
        EL2GO_DBG_PRINTF(ERROR, "TCP connection to %s:%u failed: -0x%04x\n", ctx->hostname,
                         ctx->port, -ret);
        status = EL2GO_STATUS_NET_CRYPTO_CONNECT_FAILED;
        goto cleanup_net;
    }

    /* Set blocking mode */
    ret = mbedtls_net_set_block(&ctx->net_ctx);
    if (ret != 0) {
        EL2GO_DBG_PRINTF(ERROR, "Failed to set blocking mode: -0x%04x\n", -ret);
        status = EL2GO_STATUS_NET_CRYPTO_CONNECT_FAILED;
        goto cleanup_net;
    }

    /* Configure certificate verification */
    if (ctx->ca_cert_set) {
        /* CA cert was set, enable verification */
        EL2GO_DBG_PRINTF(VERBOSE, "Server certificate verification enabled\n");
        mbedtls_ssl_conf_authmode(&ctx->conf, MBEDTLS_SSL_VERIFY_REQUIRED);
        mbedtls_ssl_conf_ca_chain(&ctx->conf, &ctx->ca_cert, NULL);
    } else {
        /* No CA cert, skip verification */
        mbedtls_ssl_conf_authmode(&ctx->conf, MBEDTLS_SSL_VERIFY_NONE);
        EL2GO_DBG_PRINTF(VERBOSE, "Server certificate verification disabled\n");
    }

    /* Configure RNG using compatibility layer */
    ret = mbedtls_compat_ssl_conf_rng(&ctx->conf, ctx->rng_ctx);
    if (ret != 0) {
        EL2GO_DBG_PRINTF(ERROR, "Failed to configure RNG: -0x%04x\n", -ret);
        status = EL2GO_STATUS_NET_CRYPTO_CONFIG_FAILED;
        goto cleanup_net;
    }

    /* Configure max fragment length based on available memory */
    status = configure_max_fragment_len(&ctx->conf);
    if (status != EL2GO_STATUS_SUCCESS)
        goto cleanup_net;

    /* Configure client certificate and key if available */
    if (ctx->cli_cert_set && mbedtls_compat_pk_has_key(&ctx->pkey)) {
        EL2GO_DBG_PRINTF(VERBOSE, "Configuring client certificate and key\n");
        ret = mbedtls_ssl_conf_own_cert(&ctx->conf, &ctx->cli_cert, &ctx->pkey);
        if (ret != 0) {
            EL2GO_DBG_PRINTF(ERROR, "Set client cert failed: -0x%04x\n", -ret);
            status = EL2GO_STATUS_NET_CRYPTO_INVALID_CERT;
            goto cleanup_net;
        }
    } else {
        EL2GO_DBG_PRINTF(VERBOSE, "No client certificate configured\n");
    }

    /* Filter cipher suites to match the configured key size */
    filter_ciphers_by_key_bitlen(ctx);

    /* Limit how long a single SSL record read may block waiting for data.
     * See NET_CRYPTO_SSL_READ_TIMEOUT_MS for the chosen value. */
    mbedtls_ssl_conf_read_timeout(&ctx->conf, NET_CRYPTO_SSL_READ_TIMEOUT_MS);

    /* Setup SSL context */
    ret = mbedtls_ssl_setup(&ctx->ssl, &ctx->conf);
    if (ret != 0) {
        EL2GO_DBG_PRINTF(ERROR, "SSL setup failed: -0x%04x\n", -ret);
        status = EL2GO_STATUS_NET_CRYPTO_SSL_SETUP_FAILED;
        goto cleanup_net;
    }

    /* Set hostname for SNI */
    EL2GO_DBG_PRINTF(VERBOSE, "Setting SNI hostname: %s\n", ctx->hostname);
    ret = mbedtls_ssl_set_hostname(&ctx->ssl, ctx->hostname);
    if (ret != 0) {
        EL2GO_DBG_PRINTF(ERROR, "Failed to set hostname: -0x%04x\n", -ret);
        status = EL2GO_STATUS_NET_CRYPTO_HOSTNAME_FAILED;
        goto cleanup_ssl;
    }

    /* Set BIO callbacks */
    mbedtls_ssl_set_bio(&ctx->ssl, &ctx->net_ctx, mbedtls_net_send, mbedtls_net_recv,
                        mbedtls_net_recv_timeout);

    /* Perform SSL/TLS handshake */
    EL2GO_DBG_PRINTF(VERBOSE, "Starting TLS handshake with %s:%u\n", ctx->hostname, ctx->port);
    while ((ret = mbedtls_ssl_handshake(&ctx->ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            status = handle_handshake_failure(ctx, ret);
            EL2GO_DBG_PRINTF(/* handshake failure */
                             ERROR, "Handshake with %s:%u failed: -0x%04x\n", ctx->hostname,
                             ctx->port, -ret);
            goto cleanup_ssl;
        }
    }

    ctx->connected = true;
    EL2GO_DBG_PRINTF(VERBOSE, "SSL/TLS connection established to %s:%u\n", ctx->hostname,
                     ctx->port);

    /* Log negotiated ALPN protocol — only if ALPN was configured.
     * If the server ignored the extension, "none" is a useful diagnostic. */
    if (ctx->alpn_set) {
        const char *alpn = mbedtls_ssl_get_alpn_protocol(&ctx->ssl);
        (void)alpn;
        EL2GO_DBG_PRINTF(VERBOSE, "ALPN negotiated: %s\n", alpn ? alpn : "none (server ignored)");
    }

    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;

cleanup_ssl:
    /* Free and re-init the SSL context so a subsequent net_crypto_connect()
     * call can safely invoke mbedtls_ssl_setup() again. A mere session reset
     * is not sufficient because mbedtls_ssl_setup() refuses to run on an
     * already-configured context and returns MBEDTLS_ERR_SSL_BAD_INPUT_DATA,
     * which causes every retry after the first failure to report
     * EL2GO_STATUS_NET_CRYPTO_SSL_SETUP_FAILED. */
    mbedtls_ssl_free(&ctx->ssl);
    mbedtls_ssl_init(&ctx->ssl);

cleanup_net:
    /* Free network context */
    mbedtls_net_free(&ctx->net_ctx);

    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}

el2go_status_t net_crypto_verify_cert(net_crypto_ctx_t *ctx, const uint8_t *crl_pem, size_t crl_len)
{
    int ret = 0;
    uint32_t verify_result = 0;
    mbedtls_x509_crl crl = { 0 };
    const mbedtls_x509_crt *peer_cert = NULL;
    el2go_status_t status = EL2GO_STATUS_SUCCESS;

    EL2GO_DBG_TRACE_FUNCTION_CALL;

    if (!ctx || !crl_pem)
        return EL2GO_STATUS_INVALID_PARAMETER;

    if (!ctx->connected) {
        EL2GO_DBG_PRINTF(ERROR, "Not connected - cannot verify certificate\n");
        return EL2GO_STATUS_INVALID_PARAMETER;
    }

    mbedtls_x509_crl_init(&crl);

    /* Parse the CRL */
    ret = mbedtls_x509_crl_parse_der(&crl, crl_pem, crl_len);
    if (ret != 0) {
        EL2GO_DBG_PRINTF(ERROR, "Failed to parse CRL: -0x%04x\n", -ret);
        status = EL2GO_STATUS_NET_CRYPTO_INVALID_CERT;
        goto exit;
    }

    /* Get peer certificate using compatibility macro */
    peer_cert = MBEDTLS_COMPAT_GET_PEER_CERT(&ctx->ssl);

    if (!peer_cert) {
        EL2GO_DBG_PRINTF(ERROR, "No peer certificate available for CRL verification\n");
        status = EL2GO_STATUS_NET_CRYPTO_INVALID_CERT;
        goto exit;
    }

    /* Verify the certificate against CA chain and CRL */
    ret = mbedtls_x509_crt_verify((mbedtls_x509_crt *)peer_cert, &ctx->ca_cert, &crl, NULL,
                                  &verify_result, NULL, NULL);

    if (verify_result != 0 || ret != 0) {
        if (verify_result != 0) {
            warn_crt_crl_period(verify_result);
            EL2GO_DBG_PRINTF(ERROR,
                             "Failed to verify server certificate with CRL (Verify: 0x%08x)\n",
                             verify_result);
        } else {
            EL2GO_DBG_PRINTF(ERROR, "Certificate verification failed: -0x%04x\n", -ret);
        }
        status = EL2GO_STATUS_NET_CRYPTO_CERT_VERIFY_FAILED;
        goto exit;
    }

    EL2GO_DBG_PRINTF(VERBOSE, "Server certificate verified successfully\n");

exit:
    mbedtls_x509_crl_free(&crl);
    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}

el2go_status_t net_crypto_disconnect(net_crypto_ctx_t *ctx)
{
    int ret = 0;

    EL2GO_DBG_TRACE_FUNCTION_CALL;

    if (!ctx)
        return EL2GO_STATUS_INVALID_PARAMETER;

    if (!ctx->connected) {
        EL2GO_DBG_PRINTF(VERBOSE, "%s: context not connected\n", __func__);
        return EL2GO_STATUS_NET_CRYPTO_NOT_CONNECTED;
    }

    /* No error checking, the connection might be closed already */
    do {
        ret = mbedtls_ssl_close_notify(&ctx->ssl);
    } while (ret == MBEDTLS_ERR_SSL_WANT_WRITE);

    /* Close the network connection */
    mbedtls_net_free(&ctx->net_ctx);

    /* Reset SSL session to allow reconnection */
    ret = mbedtls_ssl_session_reset(&ctx->ssl);
    if (ret != 0) {
        EL2GO_DBG_PRINTF(ERROR, "SSL session reset failed: -0x%04x\n", -ret);
        return EL2GO_STATUS_NET_CRYPTO_SSL_SETUP_FAILED;
    }

    ctx->connected = false;

    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, EL2GO_STATUS_SUCCESS);
    return EL2GO_STATUS_SUCCESS;
}

void net_crypto_free(net_crypto_ctx_t **ctx)
{
    net_crypto_ctx_t *ctx_ptr;

    EL2GO_DBG_TRACE_FUNCTION_CALL;

    if (!ctx || !*ctx)
        return;

    ctx_ptr = *ctx;

    /* Disconnect if still connected */
    if (ctx_ptr->connected)
        (void)net_crypto_disconnect(ctx_ptr);

    /* Free all mbedTLS structures */
    mbedtls_ssl_free(&ctx_ptr->ssl);
    mbedtls_ssl_config_free(&ctx_ptr->conf);
    mbedtls_compat_rng_free(ctx_ptr->rng_ctx);
    mbedtls_x509_crt_free(&ctx_ptr->ca_cert);
    mbedtls_x509_crt_free(&ctx_ptr->cli_cert);
    mbedtls_pk_free(&ctx_ptr->pkey);

    /* Free hostname */
    if (ctx_ptr->hostname) {
        osal_free(ctx_ptr->hostname);
        ctx_ptr->hostname = NULL;
    }

    /* Free allocated cipher suites buffer - mbedTLS does NOT copy this */
    if (ctx_ptr->ciphers) {
        osal_free(ctx_ptr->ciphers);
        ctx_ptr->ciphers = NULL;
    }

    /* Free allocated curves buffer - mbedTLS does NOT copy this */
    if (ctx_ptr->curves) {
        osal_free(ctx_ptr->curves);
        ctx_ptr->curves = NULL;
    }

    /* Free the context itself */
    osal_free(ctx_ptr);
    *ctx = NULL;
}

int net_crypto_read(net_crypto_ctx_t *ctx, uint8_t *buffer, size_t len)
{
    int ret = 0;

    EL2GO_DBG_TRACE_FUNCTION_CALL;

    if (!ctx || !buffer)
        return -1;

    if (!ctx->connected) {
        EL2GO_DBG_PRINTF(ERROR, "Not connected - cannot read\n");
        return -1;
    }

    ret = mbedtls_ssl_read(&ctx->ssl, buffer, len);
    if (ret < 0) {
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            return 0; /* no data available yet, not fatal */
        }
        EL2GO_DBG_PRINTF(ERROR, "SSL read failed: -0x%04x\n", -ret);
        return ret;
    }

    return ret;
}

int net_crypto_write(net_crypto_ctx_t *ctx, const uint8_t *buffer, size_t len)
{
    int ret = 0;

    EL2GO_DBG_TRACE_FUNCTION_CALL;

    /* Empty payload - nothing to write, not an error */
    if (len == 0)
        return 0;

    if (!ctx || !buffer)
        return -1;

    if (!ctx->connected) {
        EL2GO_DBG_PRINTF(ERROR, "Not connected - cannot write\n");
        return -1;
    }

    ret = mbedtls_ssl_write(&ctx->ssl, buffer, len);
    if (ret < 0) {
        EL2GO_DBG_PRINTF(ERROR, "SSL write failed: -0x%04x\n", -ret);
        return ret;
    }

    return ret;
}

el2go_status_t net_crypto_set_alpn(net_crypto_ctx_t *ctx, const char **alpn_protos)
{
    int ret = 0;

    EL2GO_DBG_TRACE_FUNCTION_CALL;

    if (!ctx || !alpn_protos)
        return EL2GO_STATUS_INVALID_PARAMETER;

    if (!ctx->configured) {
        EL2GO_DBG_PRINTF(ERROR, "Set ALPN: context not configured\n");
        return EL2GO_STATUS_INVALID_PARAMETER;
    }

    ret = mbedtls_ssl_conf_alpn_protocols(&ctx->conf, alpn_protos);
    if (ret != 0) {
        EL2GO_DBG_PRINTF(ERROR, "mbedtls_ssl_conf_alpn_protocols failed: -0x%04x\n", -ret);
        return EL2GO_STATUS_NET_CRYPTO_CONFIG_FAILED;
    }

    ctx->alpn_set = true;

    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, EL2GO_STATUS_SUCCESS);
    return EL2GO_STATUS_SUCCESS;
}

el2go_status_t net_crypto_set_curves(net_crypto_ctx_t *ctx, const el2go_curve_list_t *curve_list)
{
    void *curves = NULL;
    int num_curves = 0;
    size_t max_curves = 0;
    el2go_status_t status = EL2GO_STATUS_SUCCESS;
    size_t element_size = 0;

    EL2GO_DBG_TRACE_FUNCTION_CALL;

    if (!ctx)
        return EL2GO_STATUS_INVALID_PARAMETER;

    if (!ctx->configured) {
        EL2GO_DBG_PRINTF(ERROR, "Set curves: context not configured\n");
        return EL2GO_STATUS_INVALID_PARAMETER;
    }

    if (!curve_list || !curve_list->curves || curve_list->count == 0) {
        EL2GO_DBG_PRINTF(VERBOSE, "Use mbedTLS default curves\n");
        return EL2GO_STATUS_SUCCESS;
    }

    /* Free previously allocated curves if any */
    if (ctx->curves) {
        osal_free(ctx->curves);
        ctx->curves = NULL;
    }

    if (ADD_OVERFLOW(curve_list->count, 1, &max_curves)) {
        EL2GO_DBG_PRINTF(ERROR, "curve_list->count (%zu) too large\n", curve_list->count);
        return EL2GO_STATUS_INVALID_PARAMETER;
    }

    element_size = sizeof(mbedtls_compat_group_id_t);

    /* Allocate array for curves (+1 for terminator) */
    curves = osal_calloc(max_curves, element_size);
    if (!curves) {
        EL2GO_DBG_PRINTF(ERROR, "Failed to allocate curves array\n");
        return EL2GO_STATUS_ALLOCATION_ERROR;
    }

    /* Convert platform curves to mbedTLS format */
    num_curves = curves_to_mbedtls(curve_list, curves, max_curves);
    if (num_curves < 0) {
        EL2GO_DBG_PRINTF(ERROR, "Failed to convert curves\n");
        status = EL2GO_STATUS_NET_CRYPTO_CONFIG_FAILED;
        goto exit;
    }

    if (num_curves == 0) {
        EL2GO_DBG_PRINTF(VERBOSE, "No compatible curves found\n");
        EL2GO_DBG_PRINTF(VERBOSE, "Use mbedTLS default curves\n");
        osal_free(curves);
        ctx->curves = NULL;
        goto exit;
    }

    /* Configure curves using compatibility layer - mbedTLS stores pointer, does NOT copy */
    mbedtls_compat_ssl_conf_groups(&ctx->conf, (mbedtls_compat_group_id_t *)curves);

    /* Transfer ownership to context - freed in net_crypto_free() */
    ctx->curves = curves;

    EL2GO_DBG_PRINTF(VERBOSE, "Configured %d curves\n", num_curves);

exit:
    /* Free temporary buffer if ownership was not transferred to context */
    if (status != EL2GO_STATUS_SUCCESS && curves)
        osal_free(curves);
    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}