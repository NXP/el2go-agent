/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Zephyr mbedTLS implementation of el2go_mqtt_verify().
 *
 * Overrides the weak default in el2go_mqtt.c.  After provisioning, this
 * module verifies that the credentials stored in the PSA keystore by the
 * RTP agent are functional by performing a TLS handshake against the
 * configured MQTT broker.
 *
 * Supported backends (selected at build time):
 *   CONFIG_EL2GO_RTP_MQTT_AWS   - AWS IoT Core
 *                                 key  PSA ID CONFIG_EL2GO_RTP_MQTT_AWS_KEY_ID (default 0x83000101)
 *                                 cert PSA ID CONFIG_EL2GO_RTP_MQTT_AWS_CERT_ID (default 0x83000102)
 *   CONFIG_EL2GO_RTP_MQTT_AZURE - Azure IoT Hub via DPS
 *                                 key  PSA ID CONFIG_EL2GO_RTP_MQTT_AZURE_KEY_ID (default 0x83000211)
 *                                 cert PSA ID CONFIG_EL2GO_RTP_MQTT_AZURE_CERT_ID (default 0x83000212)
 *
 * Transport: mbedTLS socket (net_crypto layer) with PSA opaque key handle.
 */

#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/net/socket.h>
#include <zephyr/logging/log.h>

#include "psa/crypto.h"
#include "mbedtls/ssl.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/error.h"
#include "mbedtls/pk.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

#include "net_crypto/net_crypto.h"
#include "el2go_mqtt.h"
#include "el2go_mqtt_config.h"

LOG_MODULE_REGISTER(el2go_mqtt, LOG_LEVEL_INF);

/* -------------------------------------------------------------------------
 * Key/cert PSA IDs for each MQTT backend - configurable via Kconfig
 * ------------------------------------------------------------------------- */
#define MQTT_AWS_KEY_ID ((psa_key_id_t)CONFIG_EL2GO_RTP_MQTT_AWS_KEY_ID)
#define MQTT_AWS_CERT_ID ((psa_storage_uid_t)CONFIG_EL2GO_RTP_MQTT_AWS_CERT_ID)
#define MQTT_AZURE_KEY_ID ((psa_key_id_t)CONFIG_EL2GO_RTP_MQTT_AZURE_KEY_ID)
#define MQTT_AZURE_CERT_ID ((psa_storage_uid_t)CONFIG_EL2GO_RTP_MQTT_AZURE_CERT_ID)

/* MQTT port (TLS) */
#define MQTT_TLS_PORT "8883"

/* Maximum DER certificate size exported from PSA ITS */
#define CERT_BUF_LEN 2048U

/* -------------------------------------------------------------------------
 * Internal helpers
 * ------------------------------------------------------------------------- */

/* Export a raw certificate blob from PSA ITS by UID and load it into
 * an mbedTLS X.509 certificate chain object. */
static int load_cert_from_psa_its(mbedtls_x509_crt *chain, psa_storage_uid_t uid)
{
    psa_status_t psa_rc;
    static uint8_t cert_buf[CERT_BUF_LEN];
    size_t cert_len = 0;

    psa_rc = psa_its_get(uid, 0, sizeof(cert_buf), cert_buf, &cert_len);
    if (psa_rc != PSA_SUCCESS) {
        LOG_ERR("psa_its_get(0x%08x) failed: %d", (unsigned)uid, psa_rc);
        return -EIO;
    }

    int rc = mbedtls_x509_crt_parse(chain, cert_buf, cert_len);
    if (rc != 0) {
        LOG_ERR("mbedtls_x509_crt_parse failed: -0x%04x", (unsigned)(-rc));
        return -EINVAL;
    }

    LOG_INF("Certificate loaded from PSA ITS UID 0x%08x (%zu bytes)", (unsigned)uid, cert_len);
    return 0;
}

/* Set up an mbedTLS PK context backed by a PSA opaque key.
 * The caller must call mbedtls_pk_free() when done. */
static int setup_opaque_key(mbedtls_pk_context *pk, psa_key_id_t key_id)
{
    int rc = mbedtls_pk_setup_opaque(pk, key_id);
    if (rc != 0) {
        LOG_ERR("mbedtls_pk_setup_opaque(0x%08x) failed: -0x%04x", key_id, (unsigned)(-rc));
        return -EINVAL;
    }
    LOG_INF("PSA opaque key 0x%08x loaded into PK context", key_id);
    return 0;
}

/* Perform the actual TLS connect + DISCONNECT sequence to verify credentials.
 * hostname:     DNS name or IP of the MQTT broker
 * port_str:     port as string, e.g. "8883"
 * key_id:       PSA key ID of the device private key
 * cert_uid:     PSA ITS UID of the device certificate (DER blob)
 * alpn:         ALPN protocol string array (NULL-terminated), or NULL
 * root_ca_der:  DER-encoded root CA certificate blob, or NULL to skip
 * root_ca_len:  byte length of root_ca_der (ignored when NULL)
 */
/*
 * TLS context block - heap-allocated to avoid exhausting the main thread
 * stack (mbedTLS structures are several kilobytes in total).
 */
struct tls_ctx {
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt device_cert;
    mbedtls_x509_crt ca_cert;
    mbedtls_pk_context pk;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
};

static int do_tls_verify(const char *hostname, const char *port_str, psa_key_id_t key_id,
                         psa_storage_uid_t cert_uid, const char **alpn_list,
                         const unsigned char *root_ca_der, size_t root_ca_len)
{
    int rc = 0;
    net_crypto_ctx_t *net_ctx = NULL;

    struct tls_ctx *ctx = k_malloc(sizeof(struct tls_ctx));
    if (ctx == NULL) {
        LOG_ERR("Failed to allocate TLS context (%zu bytes)", sizeof(struct tls_ctx));
        return -ENOMEM;
    }

    mbedtls_ssl_context *ssl = &ctx->ssl;
    mbedtls_ssl_config *conf = &ctx->conf;
    mbedtls_x509_crt *device_cert = &ctx->device_cert;
    mbedtls_x509_crt *ca_cert = &ctx->ca_cert;
    mbedtls_pk_context *pk = &ctx->pk;
    mbedtls_entropy_context *entropy = &ctx->entropy;
    mbedtls_ctr_drbg_context *ctr_drbg = &ctx->ctr_drbg;

    mbedtls_ssl_init(ssl);
    mbedtls_ssl_config_init(conf);
    mbedtls_x509_crt_init(device_cert);
    mbedtls_x509_crt_init(ca_cert);
    mbedtls_pk_init(pk);
    mbedtls_entropy_init(entropy);
    mbedtls_ctr_drbg_init(ctr_drbg);

    /* Seed DRBG */
    rc = mbedtls_ctr_drbg_seed(ctr_drbg, mbedtls_entropy_func, entropy,
                               (const unsigned char *)"el2go_mqtt", 10);
    if (rc != 0) {
        LOG_ERR("DRBG seed failed: -0x%04x", (unsigned)(-rc));
        goto out;
    }

    /* Load device certificate from PSA ITS */
    rc = load_cert_from_psa_its(device_cert, (psa_storage_uid_t)cert_uid);
    if (rc != 0) {
        goto out;
    }

    /* Load opaque private key from PSA key store */
    rc = setup_opaque_key(pk, key_id);
    if (rc != 0) {
        goto out;
    }

    /* Configure TLS client */
    rc = mbedtls_ssl_config_defaults(conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
                                     MBEDTLS_SSL_PRESET_DEFAULT);
    if (rc != 0) {
        LOG_ERR("ssl_config_defaults failed: -0x%04x", (unsigned)(-rc));
        goto out;
    }

    mbedtls_ssl_conf_rng(conf, mbedtls_ctr_drbg_random, ctr_drbg);

    /* Load root CA and require server certificate verification */
    if (root_ca_der != NULL && root_ca_len > 0U) {
        rc = mbedtls_x509_crt_parse(ca_cert, root_ca_der, root_ca_len);
        if (rc != 0) {
            LOG_ERR("root CA parse failed: -0x%04x", (unsigned)(-rc));
            goto out;
        }
        mbedtls_ssl_conf_ca_chain(conf, ca_cert, NULL);
        mbedtls_ssl_conf_authmode(conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    } else {
        mbedtls_ssl_conf_authmode(conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    }

    /* Attach device cert + key */
    rc = mbedtls_ssl_conf_own_cert(conf, device_cert, pk);
    if (rc != 0) {
        LOG_ERR("ssl_conf_own_cert failed: -0x%04x", (unsigned)(-rc));
        goto out;
    }

    /* ALPN protocols if provided */
    if (alpn_list != NULL) {
        rc = mbedtls_ssl_conf_alpn_protocols(conf, alpn_list);
        if (rc != 0) {
            LOG_ERR("ssl_conf_alpn_protocols failed: -0x%04x", (unsigned)(-rc));
            goto out;
        }
    }

    /* SNI hostname */
    rc = mbedtls_ssl_setup(ssl, conf);
    if (rc != 0) {
        LOG_ERR("ssl_setup failed: -0x%04x", (unsigned)(-rc));
        goto out;
    }

    rc = mbedtls_ssl_set_hostname(ssl, hostname);
    if (rc != 0) {
        LOG_ERR("ssl_set_hostname failed: -0x%04x", (unsigned)(-rc));
        goto out;
    }

    /* Open TCP connection via net_crypto */
    rc = net_crypto_connect(&net_ctx, hostname, port_str);
    if (rc != 0) {
        LOG_ERR("net_crypto_connect to %s:%s failed (%d)", hostname, port_str, rc);
        goto out;
    }

    mbedtls_ssl_set_bio(ssl, net_ctx, net_crypto_send, net_crypto_recv, NULL);

    /* TLS handshake */
    LOG_INF("TLS handshake to %s:%s ...", hostname, port_str);
    do {
        rc = mbedtls_ssl_handshake(ssl);
    } while (rc == MBEDTLS_ERR_SSL_WANT_READ || rc == MBEDTLS_ERR_SSL_WANT_WRITE);

    if (rc != 0) {
        char err_buf[80];
        mbedtls_strerror(rc, err_buf, sizeof(err_buf));
        LOG_ERR("TLS handshake failed: -0x%04x (%s)", (unsigned)(-rc), err_buf);
        rc = -ECONNREFUSED;
        goto out_disconnect;
    }

    LOG_INF("TLS handshake succeeded - credentials verified");
    rc = 0;

    mbedtls_ssl_close_notify(ssl);

out_disconnect:
    net_crypto_disconnect(net_ctx);
    net_ctx = NULL;

out:
    mbedtls_ssl_free(ssl);
    mbedtls_ssl_config_free(conf);
    mbedtls_x509_crt_free(device_cert);
    mbedtls_x509_crt_free(ca_cert);
    mbedtls_pk_free(pk);
    mbedtls_ctr_drbg_free(ctr_drbg);
    mbedtls_entropy_free(entropy);
    k_free(ctx);

    return rc;
}

/* -------------------------------------------------------------------------
 * Public API - Zephyr override of the weak default
 * ------------------------------------------------------------------------- */

int el2go_mqtt_verify(el2go_keystore_t *keystore)
{
    int rc = 0;

    ARG_UNUSED(keystore);

#if defined(CONFIG_EL2GO_RTP_MQTT_AWS)
    {
        /* AWS IoT Core: uses x-amzn-mqtt-ca ALPN for port 443, or direct
         * mTLS on port 8883 without ALPN. */
        const char *hostname = CONFIG_EL2GO_RTP_MQTT_AWS_HOSTNAME;
        LOG_INF("Verifying AWS IoT Core credentials against %s", hostname);

        rc = do_tls_verify(hostname, MQTT_TLS_PORT, (psa_key_id_t)MQTT_AWS_KEY_ID,
                           (psa_storage_uid_t)MQTT_AWS_CERT_ID, NULL, AWS_ROOT_SERVER_CERT,
                           AWS_ROOT_SERVER_CERT_SIZE);
        if (rc != 0) {
            LOG_ERR("AWS MQTT verify failed (%d)", rc);
            return rc;
        }
        LOG_INF("AWS IoT Core MQTT credentials verified");
    }
#endif /* CONFIG_EL2GO_RTP_MQTT_AWS */

#if defined(CONFIG_EL2GO_RTP_MQTT_AZURE)
    {
        /* Azure IoT Hub DPS: TLS client auth on port 8883. */
        const char *hostname = CONFIG_EL2GO_RTP_MQTT_AZURE_HOSTNAME;
        LOG_INF("Verifying Azure IoT Hub credentials against %s", hostname);

        rc = do_tls_verify(hostname, MQTT_TLS_PORT, (psa_key_id_t)MQTT_AZURE_KEY_ID,
                           (psa_storage_uid_t)MQTT_AZURE_CERT_ID, NULL, AZURE_ROOT_SERVER_CERT,
                           AZURE_ROOT_SERVER_CERT_SIZE);
        if (rc != 0) {
            LOG_ERR("Azure MQTT verify failed (%d)", rc);
            return rc;
        }
        LOG_INF("Azure IoT Hub MQTT credentials verified");
    }
#endif /* CONFIG_EL2GO_RTP_MQTT_AZURE */

#if !defined(CONFIG_EL2GO_RTP_MQTT_AWS) && !defined(CONFIG_EL2GO_RTP_MQTT_AZURE)
    LOG_WRN("No MQTT backend selected - enable CONFIG_EL2GO_RTP_MQTT_AWS or "
            "CONFIG_EL2GO_RTP_MQTT_AZURE");
#endif

    return rc;
}
