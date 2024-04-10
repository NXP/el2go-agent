/* 
 * Copyright 2024 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 * 
 */

#include <iot_agent_mqtt_zephyr.h>
#include <nxp_iot_agent_macros.h>

#include <zephyr/net/mqtt.h>
#include <zephyr/data/json.h>

#include <network_mbedtls.h>

// MQTT CONFIG

#define MQTT_BUFFER_SIZE 256U

static uint8_t rx_buffer[MQTT_BUFFER_SIZE];
static uint8_t tx_buffer[MQTT_BUFFER_SIZE];

static struct mqtt_client client_ctx;

// COMMON PROVIDER CONFIG

#define MQTT_CONNECTION_RETRY_COUNT 5U

#define MQTT_CONNACK_WAIT_MSEC 10000U
#define MQTT_SUBACK_WAIT_MSEC  5000U
#define MQTT_PUBACK_WAIT_MSEC  MQTT_SUBACK_WAIT_MSEC

#define MQTT_DATA  "Hello from Zephyr"
#define MQTT_PUBLISH_ATTEMPTS   4U

static K_SEM_DEFINE(disconnected, 0U, 1U);
static K_SEM_DEFINE(connected, 0U, 1U);

// AWS CONFIG

#define AWS_MQTT_TOPIC "sdk/test/cpp"

static const char AWS_SERVER_ROOT_CERTIFICATE_PEM[] =
"-----BEGIN CERTIFICATE-----\n"
"MIIDQTCCAimgAwIBAgITBmyfz5m/jAo54vB4ikPmljZbyjANBgkqhkiG9w0BAQsF\n"
"ADA5MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6\n"
"b24gUm9vdCBDQSAxMB4XDTE1MDUyNjAwMDAwMFoXDTM4MDExNzAwMDAwMFowOTEL\n"
"MAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEZMBcGA1UEAxMQQW1hem9uIFJv\n"
"b3QgQ0EgMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALJ4gHHKeNXj\n"
"ca9HgFB0fW7Y14h29Jlo91ghYPl0hAEvrAIthtOgQ3pOsqTQNroBvo3bSMgHFzZM\n"
"9O6II8c+6zf1tRn4SWiw3te5djgdYZ6k/oI2peVKVuRF4fn9tBb6dNqcmzU5L/qw\n"
"IFAGbHrQgLKm+a/sRxmPUDgH3KKHOVj4utWp+UhnMJbulHheb4mjUcAwhmahRWa6\n"
"VOujw5H5SNz/0egwLX0tdHA114gk957EWW67c4cX8jJGKLhD+rcdqsq08p8kDi1L\n"
"93FcXmn/6pUCyziKrlA4b9v7LWIbxcceVOF34GfID5yHI9Y/QCB/IIDEgEw+OyQm\n"
"jgSubJrIqg0CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMC\n"
"AYYwHQYDVR0OBBYEFIQYzIU07LwMlJQuCFmcx7IQTgoIMA0GCSqGSIb3DQEBCwUA\n"
"A4IBAQCY8jdaQZChGsV2USggNiMOruYou6r4lK5IpDB/G/wkjUu0yKGX9rbxenDI\n"
"U5PMCCjjmCXPI6T53iHTfIUJrU6adTrCC2qJeHZERxhlbI1Bjjt/msv0tadQ1wUs\n"
"N+gDS63pYaACbvXy8MWy7Vu33PqUXHeeE6V/Uq2V8viTO96LXFvKWlJbYK8U90vv\n"
"o/ufQJVtMVT8QtPHRh8jrdkPSHCa2XV4cdFyQzR1bldZwgJcJmApzyMZFo6IQ6XU\n"
"5MsI+yMRQ+hDKXJioaldXgjUkK642M4UwtBV8ob2xJNDd2ZhwLnoQdeXeGADbkpy\n"
"rqXRfboQnoZsG4q5WTP468SQvvG5\n"
"-----END CERTIFICATE-----\n";

// AZURE CONFIG

#define AZURE_MQTT_REGISTER_HOSTNAME      "global.azure-devices-provisioning.net"
#define AZURE_MQTT_REGISTER_PORT          8883U
#define AZURE_MQTT_REGISTRATION_MSG_TOPIC "$dps/registrations/PUT/iotdps-register/?$rid=1"
#define AZURE_MQTT_PUBLISH_MSG_OPID_AZURE "$dps/registrations/GET/iotdps-get-operationstatus/?$rid=2&operationId="
#define AZURE_MQTT_SUBSCRIBE_MSG_TOPIC    "$dps/registrations/res/#"

#define AZURE_MQTT_REGISTRATION_WAIT_COUNT 20U

static const char AZURE_SERVER_ROOT_CERTIFICATE_PEM[] =
/* DigiCert Baltimore Root */
"-----BEGIN CERTIFICATE-----\r\n"
"MIIDdzCCAl+gAwIBAgIEAgAAuTANBgkqhkiG9w0BAQUFADBaMQswCQYDVQQGEwJJ\r\n"
"RTESMBAGA1UEChMJQmFsdGltb3JlMRMwEQYDVQQLEwpDeWJlclRydXN0MSIwIAYD\r\n"
"VQQDExlCYWx0aW1vcmUgQ3liZXJUcnVzdCBSb290MB4XDTAwMDUxMjE4NDYwMFoX\r\n"
"DTI1MDUxMjIzNTkwMFowWjELMAkGA1UEBhMCSUUxEjAQBgNVBAoTCUJhbHRpbW9y\r\n"
"ZTETMBEGA1UECxMKQ3liZXJUcnVzdDEiMCAGA1UEAxMZQmFsdGltb3JlIEN5YmVy\r\n"
"VHJ1c3QgUm9vdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKMEuyKr\r\n"
"mD1X6CZymrV51Cni4eiVgLGw41uOKymaZN+hXe2wCQVt2yguzmKiYv60iNoS6zjr\r\n"
"IZ3AQSsBUnuId9Mcj8e6uYi1agnnc+gRQKfRzMpijS3ljwumUNKoUMMo6vWrJYeK\r\n"
"mpYcqWe4PwzV9/lSEy/CG9VwcPCPwBLKBsua4dnKM3p31vjsufFoREJIE9LAwqSu\r\n"
"XmD+tqYF/LTdB1kC1FkYmGP1pWPgkAx9XbIGevOF6uvUA65ehD5f/xXtabz5OTZy\r\n"
"dc93Uk3zyZAsuT3lySNTPx8kmCFcB5kpvcY67Oduhjprl3RjM71oGDHweI12v/ye\r\n"
"jl0qhqdNkNwnGjkCAwEAAaNFMEMwHQYDVR0OBBYEFOWdWTCCR1jMrPoIVDaGezq1\r\n"
"BE3wMBIGA1UdEwEB/wQIMAYBAf8CAQMwDgYDVR0PAQH/BAQDAgEGMA0GCSqGSIb3\r\n"
"DQEBBQUAA4IBAQCFDF2O5G9RaEIFoN27TyclhAO992T9Ldcw46QQF+vaKSm2eT92\r\n"
"9hkTI7gQCvlYpNRhcL0EYWoSihfVCr3FvDB81ukMJY2GQE/szKN+OMY3EU/t3Wgx\r\n"
"jkzSswF07r51XgdIGn9w/xZchMB5hbgF/X++ZRGjD8ACtPhSNzkE1akxehi/oCr0\r\n"
"Epn3o0WC4zxe9Z2etciefC7IpJ5OCBRLbf1wbWsaY71k5h+3zvDyny67G7fyUIhz\r\n"
"ksLi4xaNmjICq44Y3ekQEe5+NauQrz4wlHrQMz2nZQ/1/I6eYs9HRCwBXbsdtTLS\r\n"
"R9I4LtD+gdwyah617jzV/OeBHRnDJELqYzmp\r\n"
"-----END CERTIFICATE-----\r\n"
/*DigiCert Global Root G2*/
"-----BEGIN CERTIFICATE-----\r\n"
"MIIDjjCCAnagAwIBAgIQAzrx5qcRqaC7KGSxHQn65TANBgkqhkiG9w0BAQsFADBh\r\n"
"MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3\r\n"
"d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBH\r\n"
"MjAeFw0xMzA4MDExMjAwMDBaFw0zODAxMTUxMjAwMDBaMGExCzAJBgNVBAYTAlVT\r\n"
"MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j\r\n"
"b20xIDAeBgNVBAMTF0RpZ2lDZXJ0IEdsb2JhbCBSb290IEcyMIIBIjANBgkqhkiG\r\n"
"9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuzfNNNx7a8myaJCtSnX/RrohCgiN9RlUyfuI\r\n"
"2/Ou8jqJkTx65qsGGmvPrC3oXgkkRLpimn7Wo6h+4FR1IAWsULecYxpsMNzaHxmx\r\n"
"1x7e/dfgy5SDN67sH0NO3Xss0r0upS/kqbitOtSZpLYl6ZtrAGCSYP9PIUkY92eQ\r\n"
"q2EGnI/yuum06ZIya7XzV+hdG82MHauVBJVJ8zUtluNJbd134/tJS7SsVQepj5Wz\r\n"
"tCO7TG1F8PapspUwtP1MVYwnSlcUfIKdzXOS0xZKBgyMUNGPHgm+F6HmIcr9g+UQ\r\n"
"vIOlCsRnKPZzFBQ9RnbDhxSJITRNrw9FDKZJobq7nMWxM4MphQIDAQABo0IwQDAP\r\n"
"BgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQUTiJUIBiV\r\n"
"5uNu5g/6+rkS7QYXjzkwDQYJKoZIhvcNAQELBQADggEBAGBnKJRvDkhj6zHd6mcY\r\n"
"1Yl9PMWLSn/pvtsrF9+wX3N3KjITOYFnQoQj8kVnNeyIv/iPsGEMNKSuIEyExtv4\r\n"
"NeF22d+mQrvHRAiGfzZ0JFrabA0UWTW98kndth/Jsw1HKj2ZL7tcu7XUIOGZX1NG\r\n"
"Fdtom/DzMNU+MeKNhJ7jitralj41E6Vf8PlwUHBHQRFXGU7Aj64GxJUTFy8bJZ91\r\n"
"8rGOmaFvE7FBcf6IKshPECBV1/MUReXgRPTqh5Uykw7+U0b6LJ3/iyK5S9kJRaTe\r\n"
"pLiaWN0bfVKfjllDiIGknibVb63dDcY3fe0Dkhvld1927jyNxF1WW6LZZm6zNTfl\r\n"
"MrY=\r\n"
"-----END CERTIFICATE-----\r\n";

typedef enum { NOT_ASSIGNED, ASSIGNING, ASSIGNED } azure_registration_state_t;

typedef struct azure_registration_info_t
{
    char assignedHub[256];
    char deviceId[256];
    char registrationId[256];
    char operationId[256];
    char username[256];
    azure_registration_state_t state;
} azure_registration_info_t;

typedef struct azure_connection_info
{
    char hostname[256];
    char topic[256];
    char username[256];
} azure_connection_info_t;

struct azure_registration_state_struct
{
    const char* registrationId;
    const char* assignedHub;
    const char* deviceId;
};
        
struct azure_publish_message_struct
{
    const char* operationId;
    const char* status;
    struct azure_registration_state_struct registrationState;
};

static const struct json_obj_descr azure_registration_state_description[] =
{
    JSON_OBJ_DESCR_PRIM(struct azure_registration_state_struct, registrationId, JSON_TOK_STRING),
    JSON_OBJ_DESCR_PRIM(struct azure_registration_state_struct, assignedHub, JSON_TOK_STRING),
    JSON_OBJ_DESCR_PRIM(struct azure_registration_state_struct, deviceId, JSON_TOK_STRING)
};

static const struct json_obj_descr azure_publish_message_description[] =
{
    JSON_OBJ_DESCR_PRIM(struct azure_publish_message_struct, operationId, JSON_TOK_STRING),
    JSON_OBJ_DESCR_PRIM(struct azure_publish_message_struct, status, JSON_TOK_STRING),
    JSON_OBJ_DESCR_OBJECT(struct azure_publish_message_struct, registrationState, azure_registration_state_description)
};

static azure_registration_info_t* reg_info_p;

static K_SEM_DEFINE(subscribed, 0U, 1U);
static K_SEM_DEFINE(assigning, 0U, 1U);
static K_SEM_DEFINE(assigned, 0U, 1U);

// MQTT METHODS

int mqtt_client_custom_transport_connect(struct mqtt_client *client)
{
    return network_connect(client->transport.custom_transport_data);
}

int mqtt_client_custom_transport_write(struct mqtt_client *client, const uint8_t *data, uint32_t datalen)
{
    return network_write(client->transport.custom_transport_data, data, datalen);
}

int mqtt_client_custom_transport_write_msg(struct mqtt_client *client, const struct msghdr *message)
{
    int status = 0;
    int bytes_written = 0;

    for (int i = 0; i < message->msg_iovlen; i++)
    {
        status = network_write(client->transport.custom_transport_data, message->msg_iov[i].iov_base, message->msg_iov[i].iov_len);

        if (status < 0)
        {
            return status;
        }

        bytes_written += status;
    }

    return bytes_written;
}

int mqtt_client_custom_transport_read(struct mqtt_client *client, uint8_t *data, uint32_t buflen, bool shall_block)
{
    // Not configurable via network_read(3)
    (void)(shall_block);

    return network_read(client->transport.custom_transport_data, data, buflen);
}

int mqtt_client_custom_transport_disconnect(struct mqtt_client *client)
{
    return network_disconnect(client->transport.custom_transport_data);
}

// COMMON PROVIDER METHODS

const char *mqttEventTypeToString(enum mqtt_evt_type type)
{
    static const char *const types[] =
    {
        "CONNACK", "DISCONNECT", "PUBLISH", "PUBACK", "PUBREC",
        "PUBREL", "PUBCOMP", "SUBACK", "UNSUBACK", "PINGRESP"
    };

    return (type < ARRAY_SIZE(types)) ? types[type] : "UNKNOWN";
}

static void genericMQTTCallback(struct mqtt_client *client, const struct mqtt_evt *evt)
{
    IOT_AGENT_INFO("Received MQTT event %s", mqttEventTypeToString(evt->type));

    switch (evt->type)
    {
        case MQTT_EVT_CONNACK:
            k_sem_give(&connected);
            break;
        case MQTT_EVT_DISCONNECT:
            k_sem_give(&disconnected);
            break;
        default:
            break;
    }
}

static void cleanupMQTTClient(struct mqtt_client *client)
{
    free(client->user_name);
    client->user_name = NULL;

    mbedtls_network_context_t* network_ctx = (mbedtls_network_context_t *)client->transport.custom_transport_data;
    mbedtls_network_config_t* network_config = &network_ctx->network_config;
    mbedtls_x509_crt_free(&network_config->clicert);
    mbedtls_x509_crt_free(&network_config->ca_chain);
    free(network_config);
    network_config = NULL;
    network_free(network_ctx);
    network_ctx = NULL;
}

static iot_agent_status_t setupMQTTClient(struct mqtt_client *client, void* cb, char* client_id, char* username, char* hostname, uint16_t port, uint32_t key_id, uint32_t cert_id, const char* ca_cert, size_t ca_cert_length)
{
    iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;

    struct mqtt_utf8* user_name = NULL;
    mbedtls_network_context_t* network_ctx = NULL;
    mbedtls_network_config_t* network_config = NULL;
    uint8_t* client_cert = NULL;

    mqtt_client_init(client);

    // Buffers
    client->rx_buf = rx_buffer;
    client->rx_buf_size = MQTT_BUFFER_SIZE;
    client->tx_buf = tx_buffer;
    client->tx_buf_size = MQTT_BUFFER_SIZE;

    // Protocol specifics
    client->transport.type = MQTT_TRANSPORT_CUSTOM;
    client->protocol_version = MQTT_VERSION_3_1_1;
    client->keepalive = CONFIG_MQTT_KEEPALIVE;

    // Callback
    client->evt_cb = cb;

    // Client ID
    client->client_id.utf8 = (uint8_t *)client_id;
    client->client_id.size = strlen(client_id);

    // Username
    if (username != NULL)
    {
        user_name = malloc(sizeof(struct mqtt_utf8));
        ASSERT_OR_EXIT_STATUS_MSG(user_name != NULL, IOT_AGENT_ERROR_MEMORY, "Could not allocate username buffer");
        user_name->utf8 = (uint8_t *)username;
        user_name->size = strlen(username);
        client->user_name = user_name;
    }

    // mbedTLS network context
    network_ctx = network_new();
    ASSERT_OR_EXIT_STATUS_MSG(network_ctx != NULL, IOT_AGENT_ERROR_MEMORY, "Could not allocate network context");
    client->transport.custom_transport_data = network_ctx;

    network_config = malloc(sizeof(mbedtls_network_config_t));
    ASSERT_OR_EXIT_STATUS_MSG(network_config != NULL, IOT_AGENT_ERROR_MEMORY, "Could not allocate network config buffer");

    // Broker
    network_config->hostname = hostname;
    network_config->port = port;

    // Client Certificate
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_status_t psa_status = psa_get_key_attributes(cert_id, &attributes);
    PSA_SUCCESS_OR_EXIT_MSG("Could not get client certificate key attributes");

    size_t client_cert_size = PSA_EXPORT_KEY_OUTPUT_SIZE(psa_get_key_type(&attributes), psa_get_key_bits(&attributes));
    client_cert = malloc(client_cert_size);
    ASSERT_OR_EXIT_STATUS_MSG(client_cert != NULL, IOT_AGENT_ERROR_MEMORY, "Could not allocate client certificate buffer");

    size_t client_cert_length = 0;
    psa_status = psa_export_key(cert_id, client_cert, client_cert_size, &client_cert_length);
    PSA_SUCCESS_OR_EXIT_MSG("Could not export client certificate");
    
    mbedtls_x509_crt_init(&network_config->clicert);
    psa_status = mbedtls_x509_crt_parse(&network_config->clicert, client_cert, client_cert_length);
    PSA_SUCCESS_OR_EXIT_MSG("Could not parse client certificate");

    // CA certificate chain
    mbedtls_x509_crt_init(&network_config->ca_chain);
    psa_status = mbedtls_x509_crt_parse(&network_config->ca_chain, ca_cert, ca_cert_length);
    PSA_SUCCESS_OR_EXIT_MSG("Could not parse root certificate");

    // Configure mbedTLS network context
    psa_status = network_configure(network_ctx, network_config);
    PSA_SUCCESS_OR_EXIT_MSG("Could not configure network");

    // Client Key
    psa_status = mbedtls_pk_setup_opaque(&network_ctx->pkey, key_id);
    PSA_SUCCESS_OR_EXIT_MSG("Could not setup mbedtls opaque client key");

exit:
    free(client_cert);

    if (agent_status != IOT_AGENT_SUCCESS)
    {
        cleanupMQTTClient(client);
    }

    return agent_status;
}

static iot_agent_status_t connectMQTTClient(struct mqtt_client *client, char* service_name, bool registration)
{
    uint16_t retry_count = 0U;

    while (retry_count < MQTT_CONNECTION_RETRY_COUNT) {
        retry_count++;

        IOT_AGENT_INFO("Attempting to %s service '%s' ...", registration ? "register" : "connect to", service_name);

        if (mqtt_connect(client) != IOT_AGENT_SUCCESS)
        {
            k_msleep(MQTT_CONNACK_WAIT_MSEC);
            continue;
        }

        mqtt_input(client);

        if (k_sem_take(&connected, K_MSEC(MQTT_CONNACK_WAIT_MSEC)) == 0)
        {
            return IOT_AGENT_SUCCESS;
        }
        else if (k_sem_take(&disconnected, K_MSEC(MQTT_CONNACK_WAIT_MSEC)) == 0)
        {
            return IOT_AGENT_UPDATE_FAILED;
        }
    }

    return IOT_AGENT_FAILURE;
}

// AWS Methods

static iot_agent_status_t awsPubMqttMessage(const nxp_iot_ServiceDescriptor* service_descriptor)
{
    iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;

    k_sem_reset(&connected);
    k_sem_reset(&disconnected);

    // Setup
    agent_status = setupMQTTClient(
        &client_ctx, genericMQTTCallback, 
        service_descriptor->client_id, NULL, 
        service_descriptor->hostname, service_descriptor->port, 
        service_descriptor->client_key_sss_ref.object_id, service_descriptor->client_certificate_sss_ref.object_id, 
        AWS_SERVER_ROOT_CERTIFICATE_PEM, sizeof(AWS_SERVER_ROOT_CERTIFICATE_PEM)
    );
    AGENT_SUCCESS_OR_EXIT_MSG("Error in MQTT Agent Context initialization");

    // Connect
    agent_status = connectMQTTClient(&client_ctx, service_descriptor->client_id, false);
    AGENT_SUCCESS_OR_EXIT_MSG("Error in MQTT connection");

    // Publish
    struct mqtt_publish_param msg;
    msg.retain_flag = 0U;
    msg.message.topic.topic.utf8 = AWS_MQTT_TOPIC;
    msg.message.topic.topic.size = strlen(AWS_MQTT_TOPIC);
    msg.message.topic.qos = 0U;
    msg.message.payload.data = MQTT_DATA;
    msg.message.payload.len = sizeof(MQTT_DATA);
    msg.message_id = 1U;

    uint16_t publish_count = 0U;
    uint16_t publish_fails = 0U;
    while (publish_count < MQTT_PUBLISH_ATTEMPTS)
    {
        agent_status = mqtt_publish(&client_ctx, &msg);
        if (agent_status == IOT_AGENT_SUCCESS)
        {
            IOT_AGENT_INFO("Successfully published");
        }
        else
        {
            IOT_AGENT_INFO("Failed to publish");
            publish_fails++;
        }

        publish_count++;
        msg.message_id++;
    }

    ASSERT_OR_EXIT_MSG(publish_fails < (MQTT_PUBLISH_ATTEMPTS / 2U), "More than or equal to %d publish attempts failed (%d)", (MQTT_PUBLISH_ATTEMPTS / 2U), publish_fails);

exit:
    mqtt_disconnect(&client_ctx);
    cleanupMQTTClient(&client_ctx);
    return agent_status;
}

// AZURE METHODS

static void azureRegistrationCallback(struct mqtt_client *client, const struct mqtt_evt *evt)
{
    IOT_AGENT_INFO("Received MQTT event %s", mqttEventTypeToString(evt->type));

    char* message = NULL;

    switch (evt->type)
    {
        case MQTT_EVT_PUBLISH:
        {
            const struct mqtt_publish_param *pub = &evt->param.publish;
            const size_t message_size = pub->message.payload.len;
            char* message = malloc(message_size);
            if (message == NULL)
            {
                IOT_AGENT_ERROR("Not enough memory for publish message");
                goto exit;
            }

            if (mqtt_readall_publish_payload(client, message, message_size) < 0)
            {
                IOT_AGENT_ERROR("Failed to read publish messsage");
                goto exit;
            }

            struct azure_publish_message_struct publish_message;
            if (json_obj_parse(message, message_size, azure_publish_message_description, ARRAY_SIZE(azure_publish_message_description), &publish_message) < 0)
            {
                IOT_AGENT_ERROR("Failed to parse publish messsage");
                goto exit;
            }

            azure_registration_info_t* reg_info = reg_info_p;

            if(strcmp(publish_message.status, "assigning") == 0)
            {
                IOT_AGENT_INFO("Device State is now ASSIGNING");

                strcpy(reg_info->operationId, AZURE_MQTT_PUBLISH_MSG_OPID_AZURE);
                strcat(reg_info->operationId, publish_message.operationId);

                reg_info->state = ASSIGNING;
                k_sem_give(&assigning);
            }
            else if(strcmp(publish_message.status, "assigned") == 0)
            {
                IOT_AGENT_INFO("Device State is now ASSIGNED");

                strcpy(reg_info->registrationId, publish_message.registrationState.registrationId);
                strcpy(reg_info->assignedHub, publish_message.registrationState.assignedHub);
                strcpy(reg_info->deviceId, publish_message.registrationState.deviceId);

                reg_info->state = ASSIGNED;
                k_sem_give(&assigned);
            }
            break;
        }
        case MQTT_EVT_CONNACK:
            k_sem_give(&connected);
            break;
        case MQTT_EVT_DISCONNECT:
            k_sem_give(&disconnected);
            break;
        case MQTT_EVT_SUBACK:
            k_sem_give(&subscribed);
            break;
        default:
            break;
    }

exit:
    free(message);
}

static iot_agent_status_t azureFormatRegistrationUsername(azure_registration_info_t* reg_info, const char* id_scope, const char* registration_id)
{
    int result = snprintf(reg_info->username, sizeof(reg_info->username), "%s/registrations/%s/api-version=2018-11-01&ClientVersion=1.4.0", id_scope, registration_id);

    if (result < 0 || result >= sizeof(reg_info->username))
    {
        return IOT_AGENT_FAILURE;
    }

    return IOT_AGENT_SUCCESS;
}

static iot_agent_status_t azureRegister(const nxp_iot_ServiceDescriptor* service_descriptor, azure_registration_info_t* reg_info)
{
    iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;

    k_sem_reset(&connected);
    k_sem_reset(&disconnected);
    k_sem_reset(&subscribed);
    k_sem_reset(&assigning);
    k_sem_reset(&assigned);

    // Setup
    agent_status = azureFormatRegistrationUsername(reg_info, service_descriptor->azure_id_scope, service_descriptor->azure_registration_id);
    AGENT_SUCCESS_OR_EXIT_MSG("Error formatting Azure registration username");

    agent_status = setupMQTTClient(
        &client_ctx, azureRegistrationCallback, 
        service_descriptor->azure_registration_id, reg_info->username, 
        AZURE_MQTT_REGISTER_HOSTNAME, AZURE_MQTT_REGISTER_PORT, 
        service_descriptor->client_key_sss_ref.object_id, service_descriptor->client_certificate_sss_ref.object_id, 
        AZURE_SERVER_ROOT_CERTIFICATE_PEM, sizeof(AZURE_SERVER_ROOT_CERTIFICATE_PEM)
    );
    AGENT_SUCCESS_OR_EXIT_MSG("Error in MQTT setup");

    reg_info_p = reg_info;

    // Connect
    agent_status = connectMQTTClient(&client_ctx, service_descriptor->azure_registration_id, true);
    AGENT_SUCCESS_OR_EXIT_MSG("Error in MQTT connection");

    // Subcribe
    struct mqtt_topic topics[] =
    {
        {
            .topic =
            {
                .utf8 = AZURE_MQTT_SUBSCRIBE_MSG_TOPIC,
                .size = strlen(AZURE_MQTT_SUBSCRIBE_MSG_TOPIC)
            },
            .qos = 0U,
        }
    };
    const struct mqtt_subscription_list sub_list =
    {
        .list = topics,
        .list_count = ARRAY_SIZE(topics),
        .message_id = 1U,
    };
    agent_status = mqtt_subscribe(&client_ctx, &sub_list);
    AGENT_SUCCESS_OR_EXIT_MSG("Error in MQTT subscription");

    reg_info->state = NOT_ASSIGNED;

    mqtt_input(&client_ctx);

    agent_status = k_sem_take(&subscribed, K_MSEC(MQTT_SUBACK_WAIT_MSEC));
    AGENT_SUCCESS_OR_EXIT_MSG("Error waiting for MQTT SUBACK");

    // Publish
    struct mqtt_publish_param reg_msg;
    reg_msg.retain_flag = 0U;
    reg_msg.message.topic.topic.utf8 = AZURE_MQTT_REGISTRATION_MSG_TOPIC;
    reg_msg.message.topic.topic.size = strlen(AZURE_MQTT_REGISTRATION_MSG_TOPIC);
    reg_msg.message.topic.qos = 0U;
    reg_msg.message.payload.data = NULL;
    reg_msg.message.payload.len = 0U;
    reg_msg.message_id = 2U;

    agent_status = mqtt_publish(&client_ctx, &reg_msg);
    AGENT_SUCCESS_OR_EXIT_MSG("Error in MQTT publish");

    mqtt_input(&client_ctx);

    agent_status = k_sem_take(&assigning, K_MSEC(MQTT_PUBACK_WAIT_MSEC));
    AGENT_SUCCESS_OR_EXIT_MSG("Error waiting for device state 'ASSIGNING'");

    // Publish
    struct mqtt_publish_param reg_conf_msg;
    reg_conf_msg.retain_flag = 0U;
    reg_conf_msg.message.topic.topic.utf8 = reg_info->operationId;
    reg_conf_msg.message.topic.topic.size = strlen(reg_info->operationId);
    reg_conf_msg.message.topic.qos = 0U;
    reg_conf_msg.message.payload.data = NULL;
    reg_conf_msg.message.payload.len = 0U;
    reg_conf_msg.message_id = 3U;

    uint16_t wait_count = 0U;
    while (reg_info->state != ASSIGNED && wait_count < AZURE_MQTT_REGISTRATION_WAIT_COUNT)
    {
        agent_status = mqtt_publish(&client_ctx, &reg_conf_msg);
        AGENT_SUCCESS_OR_EXIT_MSG("Error in MQTT publish");

        mqtt_input(&client_ctx);

        if (k_sem_take(&assigned, K_MSEC(MQTT_PUBACK_WAIT_MSEC)) == 0)
        {
            break;
        }

        wait_count++;
        reg_conf_msg.message_id++;
    }

    ASSERT_OR_EXIT_MSG(reg_info->state == ASSIGNED, "Error waiting for device state 'ASSIGNED'");

exit:
    mqtt_disconnect(&client_ctx);
    cleanupMQTTClient(&client_ctx);
    return agent_status;
}

static iot_agent_status_t azureFormatConnectionInfo(azure_connection_info_t* conn_info, char* hub_name, char* device_id)
{
    int result = snprintf(conn_info->username, sizeof(conn_info->username), "%s/%s/?api-version=2018-06-30", hub_name, device_id);
    if (result < 0 || result >= sizeof(conn_info->username))
    {
          return IOT_AGENT_FAILURE;
    }

    result = snprintf(conn_info->topic, sizeof(conn_info->topic), "devices/%s/messages/events/", device_id);
    if (result < 0 || result >= sizeof(conn_info->topic))
    {
          return IOT_AGENT_FAILURE;
    }

    return IOT_AGENT_SUCCESS;
}

static iot_agent_status_t azurePub(const nxp_iot_ServiceDescriptor* service_descriptor, azure_registration_info_t* reg_info)
{
    iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;

    k_sem_reset(&connected);
    k_sem_reset(&disconnected);

    // Setup
    azure_connection_info_t conn_info = { 0 };
    agent_status = azureFormatConnectionInfo(&conn_info, reg_info->assignedHub, reg_info->deviceId);
    AGENT_SUCCESS_OR_EXIT_MSG("Error formatting Azure connection info");

    agent_status = setupMQTTClient(
        &client_ctx, genericMQTTCallback, 
        reg_info->deviceId, conn_info.username, 
        reg_info->assignedHub, AZURE_MQTT_REGISTER_PORT, 
        service_descriptor->client_key_sss_ref.object_id, service_descriptor->client_certificate_sss_ref.object_id, 
        AZURE_SERVER_ROOT_CERTIFICATE_PEM, sizeof(AZURE_SERVER_ROOT_CERTIFICATE_PEM)
    );
    AGENT_SUCCESS_OR_EXIT_MSG("Error in MQTT Agent Context initialization");

    // Connect
    agent_status = connectMQTTClient(&client_ctx, reg_info->deviceId, false);
    AGENT_SUCCESS_OR_EXIT_MSG("Error in MQTT connection");

    // Publish
    struct mqtt_publish_param msg;
    msg.retain_flag = 0U;
    msg.message.topic.topic.utf8 = conn_info.topic;
    msg.message.topic.topic.size = strlen(conn_info.topic);
    msg.message.topic.qos = 0U;
    msg.message.payload.data = MQTT_DATA;
    msg.message.payload.len = sizeof(MQTT_DATA);
    msg.message_id = 1U;

    uint16_t publish_count = 0U;
    uint16_t publish_fails = 0U;
    while (publish_count < MQTT_PUBLISH_ATTEMPTS)
    {
        agent_status = mqtt_publish(&client_ctx, &msg);
        if (agent_status == IOT_AGENT_SUCCESS)
        {
            IOT_AGENT_INFO("Successfully published");
        }
        else
        {
            IOT_AGENT_INFO("Failed to publish");
            publish_fails++;
        }

        publish_count++;
        msg.message_id++;
    }

    ASSERT_OR_EXIT_MSG(publish_fails < (MQTT_PUBLISH_ATTEMPTS / 2U), "More than or equal to %d publish attempts failed (%d)", (MQTT_PUBLISH_ATTEMPTS / 2U), publish_fails);

exit:
    mqtt_disconnect(&client_ctx);
    cleanupMQTTClient(&client_ctx);
    return agent_status;
}

static iot_agent_status_t azurePubMqttMessage(const nxp_iot_ServiceDescriptor* service_descriptor)
{
    iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;

    azure_registration_info_t reg_info = { 0 };

    agent_status = azureRegister(service_descriptor, &reg_info);
    AGENT_SUCCESS_OR_EXIT();

    agent_status = azurePub(service_descriptor, &reg_info);
    AGENT_SUCCESS_OR_EXIT();

exit:
    return agent_status;
}

// INTERFACE

static iot_agent_status_t pubCosOverRtp(iot_agent_context_t* iot_agent_context, const nxp_iot_ServiceDescriptor* service_descriptor)
{
    iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;

    switch (service_descriptor->service_type)
    {
    case nxp_iot_ServiceType_AWSSERVICE:
        agent_status = awsPubMqttMessage(service_descriptor);
        AGENT_SUCCESS_OR_EXIT();
        break;
    case nxp_iot_ServiceType_AZURESERVICE:
        agent_status = azurePubMqttMessage(service_descriptor);
        AGENT_SUCCESS_OR_EXIT();
        break;
    default:
        EXIT_STATUS_MSG(IOT_AGENT_FAILURE, "Invalid service type");
        break;
    }

exit:
    return agent_status;
}

iot_agent_status_t iot_agent_verify_mqtt_connection_cos_over_rtp(iot_agent_context_t* iot_agent_context, const nxp_iot_ServiceDescriptor* service_descriptor)
{
    iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;

    uint16_t retry_count = 0U;
    do
    {
        agent_status = pubCosOverRtp(iot_agent_context, service_descriptor);
        retry_count++;
    }
    while (agent_status == IOT_AGENT_UPDATE_FAILED && retry_count < MQTT_CONNECTION_RETRY_COUNT);
    AGENT_SUCCESS_OR_EXIT_MSG("MQTT connection test failed");

exit:
    return agent_status;
}

iot_agent_status_t iot_agent_cleanup_mqtt_config_files_cos_over_rtp(void)
{
    return IOT_AGENT_SUCCESS;
}
