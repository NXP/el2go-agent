/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Zephyr MQTT implementation of el2go_mqtt_verify().
 *
 * Overrides the weak default in el2go_mqtt.c. After provisioning, this
 * module verifies that the credentials stored in the PSA keystore by the
 * RTP agent are functional by performing a full MQTT CONNECT + PUBLISH
 * against the configured broker.
 *
 * Supported backends (selected at build time):
 *   CONFIG_EL2GO_RTP_MQTT_AWS   - AWS IoT Core, port 8883
 *   CONFIG_EL2GO_RTP_MQTT_AZURE - Azure IoT Hub via DPS, port 8883
 *
 * Transport: net_crypto (wraps full mbedTLS TLS stack internally) with a
 * PSA opaque key.  Zephyr MQTT is wired to net_crypto via custom transport
 * callbacks (CONFIG_MQTT_LIB_CUSTOM_TRANSPORT).
 */

#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/net/mqtt.h>
#include <zephyr/data/json.h>
#include "psa/crypto.h"
#include "builtin_macros.h"

#include "net_crypto.h"
#include "el2go_mqtt.h"
#include "el2go_mqtt_config.h"
#include "el2go_app_log.h"

/* -------------------------------------------------------------------------
 * Key/cert PSA IDs for each MQTT backend
 * ------------------------------------------------------------------------- */
#define MQTT_AWS_KEY_ID ((psa_key_id_t)CONFIG_EL2GO_RTP_MQTT_AWS_KEY_ID)
#define MQTT_AWS_CERT_ID ((psa_key_id_t)CONFIG_EL2GO_RTP_MQTT_AWS_CERT_ID)
#define MQTT_AZURE_KEY_ID ((psa_key_id_t)CONFIG_EL2GO_RTP_MQTT_AZURE_KEY_ID)
#define MQTT_AZURE_CERT_ID ((psa_key_id_t)CONFIG_EL2GO_RTP_MQTT_AZURE_CERT_ID)

/* -------------------------------------------------------------------------
 * MQTT tuning constants
 * ------------------------------------------------------------------------- */
#define MQTT_BUFFER_SIZE 256U
#define MQTT_CONNECTION_RETRY_COUNT 5U
#define MQTT_PUBLISH_ATTEMPTS 4U
#define MQTT_CONNACK_WAIT_MSEC 10000U
#define MQTT_SUBACK_WAIT_MSEC 5000U
#define MQTT_PUBACK_WAIT_MSEC MQTT_SUBACK_WAIT_MSEC

/* Maximum CN length extracted from certificate subject */
#define CERT_CN_MAX_LEN 128U

/* Publish payload */
#define MQTT_DATA "Hello from Zephyr"

/* -------------------------------------------------------------------------
 * AWS topic
 * ------------------------------------------------------------------------- */
#define AWS_MQTT_TOPIC "sdk/test/cpp"

/* -------------------------------------------------------------------------
 * Azure DPS constants
 * ------------------------------------------------------------------------- */
#define AZURE_MQTT_REGISTER_HOSTNAME "global.azure-devices-provisioning.net"
#define AZURE_MQTT_REGISTER_PORT 8883U
#define AZURE_MQTT_SUBSCRIBE_MSG_TOPIC "$dps/registrations/res/#"
#define AZURE_MQTT_REGISTRATION_MSG_TOPIC "$dps/registrations/PUT/iotdps-register/?$rid=1"
#define AZURE_MQTT_PUBLISH_MSG_OPID_AZURE \
    "$dps/registrations/GET/iotdps-get-operationstatus/?$rid=2&operationId="
#define AZURE_MQTT_REGISTRATION_WAIT_COUNT 20U

/* -------------------------------------------------------------------------
 * Semaphores for MQTT event signalling
 * ------------------------------------------------------------------------- */
static K_SEM_DEFINE(sem_connected, 0U, 1U);
static K_SEM_DEFINE(sem_disconnected, 0U, 1U);
static K_SEM_DEFINE(sem_subscribed, 0U, 1U);
static K_SEM_DEFINE(sem_assigning, 0U, 1U);
static K_SEM_DEFINE(sem_assigned, 0U, 1U);

/* -------------------------------------------------------------------------
 * Shared MQTT buffers and client context (one operation at a time)
 * ------------------------------------------------------------------------- */
static uint8_t rx_buffer[MQTT_BUFFER_SIZE];
static uint8_t tx_buffer[MQTT_BUFFER_SIZE];
static struct mqtt_client client_ctx;

/* -------------------------------------------------------------------------
 * Azure registration state
 * ------------------------------------------------------------------------- */
typedef enum { NOT_ASSIGNED, ASSIGNING, ASSIGNED } azure_registration_state_t;

typedef struct {
    char assignedHub[256];
    char deviceId[256];
    char registrationId[256];
    char operationId[256];
    char username[256];
    azure_registration_state_t state;
} azure_registration_info_t;

typedef struct {
    char hostname[256];
    char topic[256];
    char username[256];
} azure_connection_info_t;

/* Pointer shared between azureRegister() and the registration callback. */
static azure_registration_info_t *reg_info_p;

/* -------------------------------------------------------------------------
 * Zephyr JSON descriptors for Azure DPS PUBLISH responses
 * ------------------------------------------------------------------------- */
struct azure_registration_state_struct {
    const char *registrationId;
    const char *assignedHub;
    const char *deviceId;
};

struct azure_publish_message_struct {
    const char *operationId;
    const char *status;
    struct azure_registration_state_struct registrationState;
};

static const struct json_obj_descr azure_registration_state_description[] = {
    JSON_OBJ_DESCR_PRIM(struct azure_registration_state_struct, registrationId, JSON_TOK_STRING),
    JSON_OBJ_DESCR_PRIM(struct azure_registration_state_struct, assignedHub, JSON_TOK_STRING),
    JSON_OBJ_DESCR_PRIM(struct azure_registration_state_struct, deviceId, JSON_TOK_STRING),
};

static const struct json_obj_descr azure_publish_message_description[] = {
    JSON_OBJ_DESCR_PRIM(struct azure_publish_message_struct, operationId, JSON_TOK_STRING),
    JSON_OBJ_DESCR_PRIM(struct azure_publish_message_struct, status, JSON_TOK_STRING),
    JSON_OBJ_DESCR_OBJECT(struct azure_publish_message_struct, registrationState,
                          azure_registration_state_description),
};

/* -------------------------------------------------------------------------
 * Custom MQTT transport callbacks - backed by net_crypto
 * net_crypto_ctx_t* is stored in client->transport.custom_transport_data.
 * ------------------------------------------------------------------------- */
int mqtt_client_custom_transport_connect(struct mqtt_client *client)
{
    net_crypto_ctx_t *ctx = (net_crypto_ctx_t *)client->transport.custom_transport_data;
    el2go_status_t rc = EL2GO_STATUS_FAILURE;

    rc = net_crypto_connect(ctx);

    if (rc != EL2GO_STATUS_SUCCESS) {
        EL2GO_APP_LOG_ERROR("net_crypto_connect failed (status: %d)", rc);
        return -EIO;
    }
    return 0;
}

int mqtt_client_custom_transport_write(struct mqtt_client *client, const uint8_t *data,
                                       uint32_t datalen)
{
    net_crypto_ctx_t *ctx = (net_crypto_ctx_t *)client->transport.custom_transport_data;

    return net_crypto_write(ctx, data, (size_t)datalen);
}

int mqtt_client_custom_transport_write_msg(struct mqtt_client *client, const struct msghdr *message)
{
    int bytes_written = 0;

    for (size_t i = 0U; i < message->msg_iovlen; i++) {
        int rc = mqtt_client_custom_transport_write(client, message->msg_iov[i].iov_base,
                                                    (uint32_t)message->msg_iov[i].iov_len);
        if (rc < 0) {
            return rc;
        }
        bytes_written += rc;
    }

    return bytes_written;
}

int mqtt_client_custom_transport_read(struct mqtt_client *client, uint8_t *data, uint32_t buflen,
                                      bool shall_block)
{
    ARG_UNUSED(shall_block);
    net_crypto_ctx_t *ctx = (net_crypto_ctx_t *)client->transport.custom_transport_data;

    return net_crypto_read(ctx, data, (size_t)buflen);
}

int mqtt_client_custom_transport_disconnect(struct mqtt_client *client)
{
    net_crypto_ctx_t *ctx = (net_crypto_ctx_t *)client->transport.custom_transport_data;
    el2go_status_t rc = net_crypto_disconnect(ctx);

    return (rc == EL2GO_STATUS_SUCCESS) ? 0 : -EIO;
}

/* -------------------------------------------------------------------------
 * Certificate helpers
 * ------------------------------------------------------------------------- */

/*
 * Export a raw certificate DER blob from the PSA key store into a heap buffer.
 * On success *buf_out points to the allocated buffer (caller must k_free it)
 * and *len_out contains the certificate length.
 * Returns 0 on success, negative errno on error.
 */
static int export_cert_der_from_psa_keystore(psa_key_id_t key_id, uint8_t **buf_out,
                                             size_t *len_out)
{
    psa_status_t psa_rc;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

    psa_rc = psa_get_key_attributes(key_id, &attributes);
    if (psa_rc != PSA_SUCCESS) {
        EL2GO_APP_LOG_ERROR("psa_get_key_attributes(0x%08x) failed: %d", (unsigned)key_id, psa_rc);
        return -EIO;
    }

    size_t buf_size =
        PSA_EXPORT_KEY_OUTPUT_SIZE(psa_get_key_type(&attributes), psa_get_key_bits(&attributes));

    psa_reset_key_attributes(&attributes);

    uint8_t *buf = k_malloc(buf_size);
    if (buf == NULL) {
        EL2GO_APP_LOG_ERROR("Failed to allocate cert buffer (%zu bytes)", buf_size);
        return -ENOMEM;
    }

    size_t cert_len = 0;
    psa_rc = psa_export_key(key_id, buf, buf_size, &cert_len);
    if (psa_rc != PSA_SUCCESS) {
        EL2GO_APP_LOG_ERROR("psa_export_key(0x%08x) failed: %d", (unsigned)key_id, psa_rc);
        k_free(buf);
        return -EIO;
    }

    *buf_out = buf;
    *len_out = cert_len;
    return 0;
}

/*
 * Extract the CN value from a DER-encoded certificate into cn_buf.
 * Returns 0 on success.  On failure cn_buf is set to an empty string.
 */
static int extract_cn_from_cert(const uint8_t *cert_der, size_t cert_len, char *cn_buf,
                                size_t cn_buf_size)
{
    return (net_crypto_get_cert_cn(cert_der, cert_len, cn_buf, cn_buf_size) ==
            EL2GO_STATUS_SUCCESS) ?
               0 :
               -EINVAL;
}

/* -------------------------------------------------------------------------
 * MQTT client setup / teardown
 * ------------------------------------------------------------------------- */

/*
 * Initialise an mqtt_client and create a net_crypto context for it.
 *
 * hostname        - broker hostname (DNS or IP)
 * port            - broker port
 * key_id          - PSA opaque key ID for device private key
 * cert_key_id     - PSA key store ID of device certificate (RAW_DATA key)
 * ca_cert_der     - root CA certificate DER blob
 * ca_cert_len     - length of root CA DER blob
 * client_id       - MQTT client ID string
 * username        - MQTT username string, or NULL
 * evt_cb          - MQTT event callback
 *
 * On success the net_crypto_ctx_t* is stored in
 * client->transport.custom_transport_data.
 */
static int setupMQTTClient(struct mqtt_client *client, mqtt_evt_cb_t evt_cb, const char *client_id,
                           const char *username, const char *hostname, uint16_t port,
                           psa_key_id_t key_id, psa_key_id_t cert_key_id,
                           const uint8_t *ca_cert_der, size_t ca_cert_len)
{
    int rc = 0;
    net_crypto_ctx_t *net_ctx = NULL;
    uint8_t *cert_buf = NULL;
    size_t cert_len = 0;

    mqtt_client_init(client);

    client->rx_buf = rx_buffer;
    client->rx_buf_size = MQTT_BUFFER_SIZE;
    client->tx_buf = tx_buffer;
    client->tx_buf_size = MQTT_BUFFER_SIZE;

    client->transport.type = MQTT_TRANSPORT_CUSTOM;
    client->protocol_version = MQTT_VERSION_3_1_1;
    client->keepalive = CONFIG_MQTT_KEEPALIVE;

    client->evt_cb = evt_cb;

    client->client_id.utf8 = (uint8_t *)client_id;
    client->client_id.size = strlen(client_id);

    if (username != NULL) {
        struct mqtt_utf8 *uname = k_malloc(sizeof(struct mqtt_utf8));

        if (uname == NULL) {
            EL2GO_APP_LOG_ERROR("Failed to allocate MQTT username struct");
            return -ENOMEM;
        }
        uname->utf8 = (uint8_t *)username;
        uname->size = strlen(username);
        client->user_name = uname;
    }

    /* Create net_crypto context and configure it. */
    if (net_crypto_new(&net_ctx) != EL2GO_STATUS_SUCCESS) {
        EL2GO_APP_LOG_ERROR("net_crypto_new failed");
        rc = -ENOMEM;
        goto err_uname;
    }

    net_crypto_config_t cfg = {
        .hostname = hostname,
        .port = port,
    };

    if (net_crypto_configure(net_ctx, &cfg) != EL2GO_STATUS_SUCCESS) {
        EL2GO_APP_LOG_ERROR("net_crypto_configure failed");
        rc = -EIO;
        goto err_ctx;
    }

    /* Root CA certificate. */
    if (net_crypto_set_server_cert(net_ctx, ca_cert_der, ca_cert_len) != EL2GO_STATUS_SUCCESS) {
        EL2GO_APP_LOG_ERROR("net_crypto_set_server_cert failed");
        rc = -EIO;
        goto err_ctx;
    }

    /* Device certificate from PSA key store. */
    rc = export_cert_der_from_psa_keystore(cert_key_id, &cert_buf, &cert_len);
    if (rc != 0) {
        goto err_ctx;
    }

    if (net_crypto_set_cli_cert(net_ctx, cert_buf, cert_len) != EL2GO_STATUS_SUCCESS) {
        EL2GO_APP_LOG_ERROR("net_crypto_set_cli_cert failed");
        rc = -EIO;
        goto err_ctx;
    }

    /* PSA opaque private key. */
    if (net_crypto_associate_key(net_ctx, (uint32_t)key_id) != EL2GO_STATUS_SUCCESS) {
        EL2GO_APP_LOG_ERROR("net_crypto_associate_key(0x%08x) failed", key_id);
        rc = -EIO;
        goto err_ctx;
    }

    k_free(cert_buf);
    cert_buf = NULL;

    client->transport.custom_transport_data = net_ctx;
    return 0;

err_ctx:
    k_free(cert_buf);
    net_crypto_free(&net_ctx);
err_uname:
    k_free(client->user_name);
    client->user_name = NULL;
    return rc;
}

static void cleanupMQTTClient(struct mqtt_client *client)
{
    k_free(client->user_name);
    client->user_name = NULL;

    net_crypto_ctx_t *net_ctx = (net_crypto_ctx_t *)client->transport.custom_transport_data;

    if (net_ctx != NULL) {
        net_crypto_free(&net_ctx);
        client->transport.custom_transport_data = NULL;
    }
}

/* -------------------------------------------------------------------------
 * MQTT connection helper - retries with CONNACK wait
 * ------------------------------------------------------------------------- */
static int connectMQTTClient(struct mqtt_client *client, const char *service_name)
{
    uint16_t retry = 0U;

    while (retry < MQTT_CONNECTION_RETRY_COUNT) {
        retry++;
        k_sem_reset(&sem_connected);
        k_sem_reset(&sem_disconnected);

        int rc = mqtt_connect(client);
        if (rc != 0) {
            EL2GO_APP_LOG_ERROR("mqtt_connect failed: %d", rc);
            k_msleep(MQTT_CONNACK_WAIT_MSEC);
            continue;
        }

        /* Poll for CONNACK */
        int64_t deadline = k_uptime_get() + MQTT_CONNACK_WAIT_MSEC;
        while (k_uptime_get() < deadline) {
            mqtt_input(client);
            if (k_sem_take(&sem_connected, K_NO_WAIT) == 0) {
                return 0;
            }
            if (k_sem_take(&sem_disconnected, K_NO_WAIT) == 0) {
                return -ECONNREFUSED;
            }
            k_msleep(10);
        }

        EL2GO_APP_LOG_ERROR("No CONNACK received");
        mqtt_disconnect(client, NULL);
    }

    return -ETIMEDOUT;
}

/* -------------------------------------------------------------------------
 * Generic MQTT event callback (AWS publish, Azure hub publish)
 * ------------------------------------------------------------------------- */
static void genericMQTTCallback(struct mqtt_client *client, const struct mqtt_evt *evt)
{
    switch (evt->type) {
    case MQTT_EVT_CONNACK:
        EL2GO_APP_LOG_INFO("Received MQTT event CONNACK");
        k_sem_give(&sem_connected);
        break;
    case MQTT_EVT_DISCONNECT:
        EL2GO_APP_LOG_INFO("Received MQTT event DISCONNECT");
        k_sem_give(&sem_disconnected);
        break;
    default:
        EL2GO_APP_LOG_ERROR("Received unhandled MQTT event type: %d", (int)evt->type);
        break;
    }
}

/* -------------------------------------------------------------------------
 * Azure DPS registration event callback
 * ------------------------------------------------------------------------- */
static void azureRegistrationCallback(struct mqtt_client *client, const struct mqtt_evt *evt)
{
    switch (evt->type) {
    case MQTT_EVT_CONNACK:
        EL2GO_APP_LOG_INFO("Received MQTT event CONNACK");
        k_sem_give(&sem_connected);
        break;
    case MQTT_EVT_DISCONNECT:
        EL2GO_APP_LOG_INFO("Received MQTT event DISCONNECT");
        k_sem_give(&sem_disconnected);
        break;
    case MQTT_EVT_SUBACK:
        EL2GO_APP_LOG_INFO("Received MQTT event SUBACK");
        k_sem_give(&sem_subscribed);
        break;
    case MQTT_EVT_PUBLISH: {
        const struct mqtt_publish_param *pub = &evt->param.publish;
        const size_t msg_size = pub->message.payload.len;

        size_t alloc_size = 0U;

        if (ADD_OVERFLOW(msg_size, 1U, &alloc_size)) {
            EL2GO_APP_LOG_ERROR("DPS publish payload too large");
            break;
        }
        char *message = k_malloc(alloc_size);

        if (message == NULL) {
            EL2GO_APP_LOG_ERROR("OOM for DPS publish payload");
            break;
        }

        if (mqtt_readall_publish_payload(client, message, msg_size) < 0) {
            EL2GO_APP_LOG_ERROR("Failed to read DPS publish payload");
            k_free(message);
            break;
        }
        message[msg_size] = '\0';

        struct azure_publish_message_struct publish_msg = { 0 };

        if (json_obj_parse(message, msg_size, azure_publish_message_description,
                           ARRAY_SIZE(azure_publish_message_description), &publish_msg) < 0) {
            EL2GO_APP_LOG_ERROR("Failed to parse DPS JSON response");
            k_free(message);
            break;
        }

        azure_registration_info_t *reg = reg_info_p;

        if (publish_msg.status != NULL && strcmp(publish_msg.status, "assigning") == 0) {
            EL2GO_APP_LOG_INFO("Received MQTT event PUBLISH");
            EL2GO_APP_LOG_INFO("Device State is now ASSIGNING");
            if (publish_msg.operationId != NULL) {
                strncpy(reg->operationId, AZURE_MQTT_PUBLISH_MSG_OPID_AZURE,
                        sizeof(reg->operationId) - 1U);
                strncat(reg->operationId, publish_msg.operationId,
                        sizeof(reg->operationId) - strlen(reg->operationId) - 1U);
            }
            reg->state = ASSIGNING;
            k_sem_give(&sem_assigning);
        } else if (publish_msg.status != NULL && strcmp(publish_msg.status, "assigned") == 0) {
            EL2GO_APP_LOG_INFO("Received MQTT event PUBLISH");
            EL2GO_APP_LOG_INFO("Device State is now ASSIGNED");
            if (publish_msg.registrationState.assignedHub != NULL) {
                strncpy(reg->assignedHub, publish_msg.registrationState.assignedHub,
                        sizeof(reg->assignedHub) - 1U);
            }
            if (publish_msg.registrationState.deviceId != NULL) {
                strncpy(reg->deviceId, publish_msg.registrationState.deviceId,
                        sizeof(reg->deviceId) - 1U);
            }
            if (publish_msg.registrationState.registrationId != NULL) {
                strncpy(reg->registrationId, publish_msg.registrationState.registrationId,
                        sizeof(reg->registrationId) - 1U);
            }
            reg->state = ASSIGNED;
            k_sem_give(&sem_assigned);
        }

        k_free(message);
        break;
    }
    default:
        EL2GO_APP_LOG_ERROR("Received unhandled MQTT event type: %d", (int)evt->type);
        break;
    }
}

/* -------------------------------------------------------------------------
 * Azure username/topic formatting helpers
 * ------------------------------------------------------------------------- */
static int azureFormatRegistrationUsername(azure_registration_info_t *reg_info,
                                           const char *id_scope, const char *registration_id)
{
    int n = snprintf(reg_info->username, sizeof(reg_info->username),
                     "%s/registrations/%s/api-version=2018-11-01&ClientVersion=1.4.0", id_scope,
                     registration_id);

    if (n < 0 || (size_t)n >= sizeof(reg_info->username)) {
        EL2GO_APP_LOG_ERROR("Azure registration username truncated");
        return -ENOMEM;
    }
    return 0;
}

static int azureFormatConnectionInfo(azure_connection_info_t *conn_info, const char *hub_name,
                                     const char *device_id)
{
    int n = snprintf(conn_info->username, sizeof(conn_info->username),
                     "%s/%s/?api-version=2018-06-30", hub_name, device_id);

    if (n < 0 || (size_t)n >= sizeof(conn_info->username)) {
        EL2GO_APP_LOG_ERROR("Azure hub username truncated");
        return -ENOMEM;
    }

    n = snprintf(conn_info->topic, sizeof(conn_info->topic), "devices/%s/messages/events/",
                 device_id);

    if (n < 0 || (size_t)n >= sizeof(conn_info->topic)) {
        EL2GO_APP_LOG_ERROR("Azure hub topic truncated");
        return -ENOMEM;
    }

    return 0;
}

/* -------------------------------------------------------------------------
 * AWS IoT Core - MQTT CONNECT + PUBLISH
 * ------------------------------------------------------------------------- */
#if defined(CONFIG_EL2GO_RTP_MQTT_AWS)
static int awsPubMqttMessage(void)
{
    static const uint8_t aws_root_ca[] = AWS_ROOT_SERVER_CERT;
    char client_id[CERT_CN_MAX_LEN] = { 0 };
    int rc = 0;

    k_sem_reset(&sem_connected);
    k_sem_reset(&sem_disconnected);

    /* Determine client ID: static Kconfig value or CN from device cert. */
    if (strlen(AWS_CLIENT_ID) > 0U) {
        strncpy(client_id, AWS_CLIENT_ID, sizeof(client_id) - 1U);
    } else {
        uint8_t *cert_buf = NULL;
        size_t cert_len = 0;

        rc = export_cert_der_from_psa_keystore(MQTT_AWS_CERT_ID, &cert_buf, &cert_len);
        if (rc != 0) {
            return rc;
        }

        (void)extract_cn_from_cert(cert_buf, cert_len, client_id, sizeof(client_id));
        k_free(cert_buf);
    }

    if (client_id[0] == '\0') {
        EL2GO_APP_LOG_ERROR("AWS client ID is empty");
        return -EINVAL;
    }

    const char *hostname = AWS_HOSTNAME;

    rc = setupMQTTClient(&client_ctx, genericMQTTCallback, client_id, NULL, hostname, 8883U,
                         MQTT_AWS_KEY_ID, MQTT_AWS_CERT_ID, aws_root_ca, sizeof(aws_root_ca));
    if (rc != 0) {
        EL2GO_APP_LOG_ERROR("AWS setupMQTTClient failed (%d)", rc);
        return rc;
    }

    rc = connectMQTTClient(&client_ctx, hostname);
    if (rc != 0) {
        EL2GO_APP_LOG_ERROR("Error in MQTT connection");
        goto cleanup;
    }

    struct mqtt_publish_param msg = {
        .retain_flag = 0U,
        .message.topic.topic.utf8 = (uint8_t *)AWS_MQTT_TOPIC,
        .message.topic.topic.size = sizeof(AWS_MQTT_TOPIC) - 1U,
        .message.topic.qos = 0U,
        .message.payload.data = (uint8_t *)MQTT_DATA,
        .message.payload.len = sizeof(MQTT_DATA) - 1U,
        .message_id = 1U,
    };

    uint16_t attempts = 0U;
    uint16_t fails = 0U;

    while (attempts < MQTT_PUBLISH_ATTEMPTS) {
        if (mqtt_publish(&client_ctx, &msg) == 0) {
            EL2GO_APP_LOG_INFO("Successfully published");
        } else {
            EL2GO_APP_LOG_ERROR("Publish failed");
            fails++;
        }
        attempts++;
        msg.message_id++;
    }

    if (fails >= (MQTT_PUBLISH_ATTEMPTS / 2U)) {
        EL2GO_APP_LOG_ERROR("Too many AWS publish failures (%u/%u)", fails,
                            (uint16_t)MQTT_PUBLISH_ATTEMPTS);
        rc = -EIO;
    }

cleanup:
    mqtt_disconnect(&client_ctx, NULL);
    cleanupMQTTClient(&client_ctx);
    return rc;
}
#endif /* CONFIG_EL2GO_RTP_MQTT_AWS */

/* -------------------------------------------------------------------------
 * Azure IoT Hub via DPS - registration + publish
 * ------------------------------------------------------------------------- */
#if defined(CONFIG_EL2GO_RTP_MQTT_AZURE)

static int azureRegister(azure_registration_info_t *reg_info)
{
    static const uint8_t azure_root_ca[] = AZURE_ROOT_SERVER_CERT;
    int rc = 0;

    /* Clear the shared pointer before any early-return path so it is never
     * left pointing at a stale registration_info from a previous call. */
    reg_info_p = NULL;

    k_sem_reset(&sem_connected);
    k_sem_reset(&sem_disconnected);
    k_sem_reset(&sem_subscribed);
    k_sem_reset(&sem_assigning);
    k_sem_reset(&sem_assigned);

    /* Determine registration ID: static Kconfig or CN from device cert. */
    char reg_id[CERT_CN_MAX_LEN] = { 0 };

    if (strlen(AZURE_REGISTRATION_ID) > 0U) {
        strncpy(reg_id, AZURE_REGISTRATION_ID, sizeof(reg_id) - 1U);
    } else {
        uint8_t *cert_buf = NULL;
        size_t cert_len = 0;

        rc = export_cert_der_from_psa_keystore(MQTT_AZURE_CERT_ID, &cert_buf, &cert_len);
        if (rc != 0) {
            return rc;
        }
        (void)extract_cn_from_cert(cert_buf, cert_len, reg_id, sizeof(reg_id));
        k_free(cert_buf);
    }

    if (reg_id[0] == '\0') {
        EL2GO_APP_LOG_ERROR("Azure registration ID is empty");
        return -EINVAL;
    }

    rc = azureFormatRegistrationUsername(reg_info, AZURE_ID_SCOPE, reg_id);
    if (rc != 0) {
        return rc;
    }

    rc = setupMQTTClient(&client_ctx, azureRegistrationCallback, reg_id, reg_info->username,
                         AZURE_MQTT_REGISTER_HOSTNAME, AZURE_MQTT_REGISTER_PORT, MQTT_AZURE_KEY_ID,
                         MQTT_AZURE_CERT_ID, azure_root_ca, sizeof(azure_root_ca));
    if (rc != 0) {
        EL2GO_APP_LOG_ERROR("Azure DPS setupMQTTClient failed (%d)", rc);
        return rc;
    }

    reg_info_p = reg_info;

    rc = connectMQTTClient(&client_ctx, AZURE_MQTT_REGISTER_HOSTNAME);
    if (rc != 0) {
        EL2GO_APP_LOG_ERROR("Error in MQTT connection");
        goto cleanup;
    }

    /* Subscribe to DPS response topic. */
    struct mqtt_topic dps_topics[] = {
        {
            .topic = {
                .utf8 = (uint8_t *)AZURE_MQTT_SUBSCRIBE_MSG_TOPIC,
                .size = sizeof(AZURE_MQTT_SUBSCRIBE_MSG_TOPIC) - 1U,
            },
            .qos = 0U,
        },
    };
    const struct mqtt_subscription_list sub_list = {
        .list = (struct mqtt_topic *)dps_topics,
        .list_count = ARRAY_SIZE(dps_topics),
        .message_id = 1U,
    };

    if (mqtt_subscribe(&client_ctx, &sub_list) != 0) {
        EL2GO_APP_LOG_ERROR("Azure DPS subscribe failed");
        rc = -EIO;
        goto cleanup;
    }

    mqtt_input(&client_ctx);

    if (k_sem_take(&sem_subscribed, K_MSEC(MQTT_SUBACK_WAIT_MSEC)) != 0) {
        EL2GO_APP_LOG_ERROR("Timeout waiting for DPS SUBACK");
        rc = -ETIMEDOUT;
        goto cleanup;
    }

    /* Publish registration request. */
    struct mqtt_publish_param reg_msg = {
        .retain_flag = 0U,
        .message.topic.topic.utf8 = (uint8_t *)AZURE_MQTT_REGISTRATION_MSG_TOPIC,
        .message.topic.topic.size = sizeof(AZURE_MQTT_REGISTRATION_MSG_TOPIC) - 1U,
        .message.topic.qos = 0U,
        .message.payload.data = NULL,
        .message.payload.len = 0U,
        .message_id = 2U,
    };

    if (mqtt_publish(&client_ctx, &reg_msg) != 0) {
        EL2GO_APP_LOG_ERROR("Azure DPS register publish failed");
        rc = -EIO;
        goto cleanup;
    }

    mqtt_input(&client_ctx);

    if (k_sem_take(&sem_assigning, K_MSEC(MQTT_PUBACK_WAIT_MSEC)) != 0) {
        EL2GO_APP_LOG_ERROR("Timeout waiting for DPS ASSIGNING state");
        rc = -ETIMEDOUT;
        goto cleanup;
    }

    /* Poll for ASSIGNED state. */
    struct mqtt_publish_param poll_msg = {
        .retain_flag = 0U,
        .message.topic.topic.utf8 = (uint8_t *)reg_info->operationId,
        .message.topic.topic.size = strlen(reg_info->operationId),
        .message.topic.qos = 0U,
        .message.payload.data = NULL,
        .message.payload.len = 0U,
        .message_id = 3U,
    };

    uint16_t wait_count = 0U;

    while (reg_info->state != ASSIGNED && wait_count < AZURE_MQTT_REGISTRATION_WAIT_COUNT) {
        if (mqtt_publish(&client_ctx, &poll_msg) != 0) {
            EL2GO_APP_LOG_ERROR("Azure DPS poll publish failed");
            rc = -EIO;
            goto cleanup;
        }
        mqtt_input(&client_ctx);
        if (k_sem_take(&sem_assigned, K_MSEC(MQTT_PUBACK_WAIT_MSEC)) == 0) {
            break;
        }
        wait_count++;
        poll_msg.message_id++;
    }

    if (reg_info->state != ASSIGNED) {
        EL2GO_APP_LOG_ERROR("Timeout waiting for DPS ASSIGNED state after %u polls", wait_count);
        rc = -ETIMEDOUT;
    }

cleanup:
    mqtt_disconnect(&client_ctx, NULL);
    cleanupMQTTClient(&client_ctx);
    reg_info_p = NULL;
    return rc;
}

static int azurePub(azure_registration_info_t *reg_info)
{
    static const uint8_t azure_root_ca[] = AZURE_ROOT_SERVER_CERT;
    int rc = 0;

    k_sem_reset(&sem_connected);
    k_sem_reset(&sem_disconnected);

    azure_connection_info_t conn_info = { 0 };

    rc = azureFormatConnectionInfo(&conn_info, reg_info->assignedHub, reg_info->deviceId);
    if (rc != 0) {
        return rc;
    }

    rc = setupMQTTClient(&client_ctx, genericMQTTCallback, reg_info->deviceId, conn_info.username,
                         reg_info->assignedHub, AZURE_MQTT_REGISTER_PORT, MQTT_AZURE_KEY_ID,
                         MQTT_AZURE_CERT_ID, azure_root_ca, sizeof(azure_root_ca));
    if (rc != 0) {
        EL2GO_APP_LOG_ERROR("Azure hub setupMQTTClient failed (%d)", rc);
        return rc;
    }

    rc = connectMQTTClient(&client_ctx, reg_info->assignedHub);
    if (rc != 0) {
        EL2GO_APP_LOG_ERROR("Error in MQTT connection");
        goto cleanup;
    }

    struct mqtt_publish_param msg = {
        .retain_flag = 0U,
        .message.topic.topic.utf8 = (uint8_t *)conn_info.topic,
        .message.topic.topic.size = strlen(conn_info.topic),
        .message.topic.qos = 0U,
        .message.payload.data = (uint8_t *)MQTT_DATA,
        .message.payload.len = sizeof(MQTT_DATA) - 1U,
        .message_id = 1U,
    };

    uint16_t attempts = 0U;
    uint16_t fails = 0U;

    while (attempts < MQTT_PUBLISH_ATTEMPTS) {
        if (mqtt_publish(&client_ctx, &msg) == 0) {
            EL2GO_APP_LOG_INFO("Successfully published");
        } else {
            EL2GO_APP_LOG_ERROR("Publish failed");
            fails++;
        }
        attempts++;
        msg.message_id++;
    }

    if (fails >= (MQTT_PUBLISH_ATTEMPTS / 2U)) {
        EL2GO_APP_LOG_ERROR("Too many Azure hub publish failures (%u/%u)", fails,
                            (uint16_t)MQTT_PUBLISH_ATTEMPTS);
        rc = -EIO;
    }

cleanup:
    mqtt_disconnect(&client_ctx, NULL);
    cleanupMQTTClient(&client_ctx);
    return rc;
}

static int azurePubMqttMessage(void)
{
    azure_registration_info_t reg_info = { 0 };
    int rc;

    {
        char reg_id_azure[CERT_CN_MAX_LEN] = { 0 };
        if (strlen(AZURE_REGISTRATION_ID) > 0U) {
            strncpy(reg_id_azure, AZURE_REGISTRATION_ID, sizeof(reg_id_azure) - 1U);
        } else {
            uint8_t *cert_buf = NULL;
            size_t cert_len = 0;
            if (export_cert_der_from_psa_keystore(MQTT_AZURE_CERT_ID, &cert_buf, &cert_len) == 0) {
                (void)extract_cn_from_cert(cert_buf, cert_len, reg_id_azure, sizeof(reg_id_azure));
                k_free(cert_buf);
            }
        }
        EL2GO_APP_LOG_INFO("Attempting to register service '%s' ...", reg_id_azure);
    }
    rc = azureRegister(&reg_info);
    if (rc != 0) {
        EL2GO_APP_LOG_ERROR("Azure DPS registration failed (%d)", rc);
        return rc;
    }

    EL2GO_APP_LOG_INFO("Attempting to connect to service '%s' ...", reg_info.deviceId);
    rc = azurePub(&reg_info);
    if (rc != 0) {
        EL2GO_APP_LOG_ERROR("Azure hub publish failed (%d)", rc);
    }

    return rc;
}
#endif /* CONFIG_EL2GO_RTP_MQTT_AZURE */

/* -------------------------------------------------------------------------
 * Public API - Zephyr override of the weak default
 * ------------------------------------------------------------------------- */
int el2go_mqtt_verify(el2go_keystore_t *keystore)
{
    int rc = 0;
    ARG_UNUSED(keystore);

#if defined(CONFIG_EL2GO_RTP_MQTT_AWS)
    {
        char client_id_aws[CERT_CN_MAX_LEN] = { 0 };
        if (strlen(AWS_CLIENT_ID) > 0U) {
            strncpy(client_id_aws, AWS_CLIENT_ID, sizeof(client_id_aws) - 1U);
        } else {
            uint8_t *cert_buf = NULL;
            size_t cert_len = 0;
            if (export_cert_der_from_psa_keystore(MQTT_AWS_CERT_ID, &cert_buf, &cert_len) == 0) {
                (void)extract_cn_from_cert(cert_buf, cert_len, client_id_aws,
                                           sizeof(client_id_aws));
                k_free(cert_buf);
            }
        }
        EL2GO_APP_LOG_INFO("Attempting to connect to service '%s' ...", client_id_aws);
    }
    uint16_t aws_retry = 0U;
    do {
        rc = awsPubMqttMessage();
        aws_retry++;
    } while (rc != 0 && aws_retry < MQTT_CONNECTION_RETRY_COUNT);
    if (rc != 0) {
        EL2GO_APP_LOG_ERROR("AWS MQTT verify failed (%d)", rc);
        return rc;
    }
#endif

#if defined(CONFIG_EL2GO_RTP_MQTT_AZURE)
    uint16_t azure_retry = 0U;
    do {
        rc = azurePubMqttMessage();
        azure_retry++;
    } while (rc != 0 && azure_retry < MQTT_CONNECTION_RETRY_COUNT);
    if (rc != 0) {
        EL2GO_APP_LOG_ERROR("Azure MQTT verify failed (%d)", rc);
        return rc;
    }
#endif

    return rc;
}
