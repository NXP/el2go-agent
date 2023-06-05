/* Copyright 2020, 2021 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */


#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sm_types.h"

#ifdef _WIN32
#include <direct.h>
#include <dirent_win32.h>
#else /* ! _WIN32 */
 /* AX_EMBEDDED is defined and set by sm_types.h. Use after including sm_types.h */
#if AX_EMBEDDED
// Do not include dirent.h for KSDK
#else /* ! AX_EMBEDDED */
#include <dirent.h>
#endif /* AX_EMBEDDED */
#endif /* _WIN32 */

#include <iot_agent_mqtt_paho.h>
#include <nxp_iot_agent.h>
#include <nxp_iot_agent_macros.h>
#include <nxp_iot_agent_utils.h>
#include <nxLog_App.h>

#if IOT_AGENT_MQTT_CONNECTION_TEST_ENABLE
#include <nxp_iot_agent_session.h>
#include <network_openssl.h>
#include <MQTTClient.h>
#include "jsmn.h"

#endif

#if defined(__linux__) || defined(__CYGWIN__) || defined(__clang__)
#define DO_MKDIR(DIR_NAME) \
    mkdir((DIR_NAME), S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IXGRP | S_IROTH | S_IXOTH);
#else
#define DO_MKDIR(DIR_NAME) \
    _mkdir((DIR_NAME));
#endif

static const char path_separator =
#ifdef _WIN32
'\\';
#else
'/';
#endif

const char* goutput_directory = "output";
const char* goutput_directory_rtp = "output_rtp";

#define SERVICE_CONFIGURATION_PATTERN "config_%" PRIu64 ".txt"
#define SERVICE_CERTIFICATE_PATTERN "cert_%" PRIu64 ".pem"
#define SERVICE_KEYREF_PATTERN "keyref_%" PRIu64 ".pem"
#define SERVICE_SERVER_CERT_PATTERN "server_cert_%s_%" PRIu64 ".pem"
#define SERVICE_METADATA_PATTERN "metadata_%" PRIu64 ".txt"

#if IOT_AGENT_MQTT_CONNECTION_TEST_ENABLE
typedef struct mqtt_connection_params
{
    char address[256];
    char username[256];
    char topic[256];
    char *clientid;
    char *keypath;
    char *rootpath;
    char *payload;
    char *devcert;
} mqtt_connection_params_t;

typedef enum { NOT_ASSIGNED, ASSIGNING, ASSIGNED } registration_state;

typedef struct mqtt_azure_params
{
    registration_state state;
    char assignedHub[256];
    char operationId[256];
    char deviceId[256];
} mqtt_azure_params_t;

volatile MQTTClient_deliveryToken deliveredtoken;


void delivered(void *context, MQTTClient_deliveryToken dt);
void connlost(void *context, char *cause);
void write_error_logs(const char* message);
void delete_old_service_files(const char* output_directory);
void delete_old_service_files_folders(const char* output_directory);
int msgarrvd(void *context, char *topicName, int topicLen, MQTTClient_message *message);
int azure_callback(void *context, char *topicName, int topicLen, MQTTClient_message *message);
int network_openssl_engine_session_connect_mqtt();
int network_openssl_engine_session_disconnect_mqtt();
iot_agent_status_t get_value_from_tag(char *js, const char * key, char * value);
iot_agent_status_t connect_and_publish_message(mqtt_connection_params_t* connection_params);
iot_agent_status_t iot_agent_mqtt_connect_aws(const nxp_iot_ServiceDescriptor* service_descriptor, mqtt_connection_params_t* connection_params);
iot_agent_status_t iot_agent_mqtt_register_azure(mqtt_connection_params_t* connection_params, mqtt_azure_params_t* azure_params);
iot_agent_status_t iot_agent_mqtt_connect_azure(mqtt_connection_params_t* connection_params, mqtt_azure_params_t* azure_params);
iot_agent_status_t iot_agent_mqtt_register_and_connect_azure(const nxp_iot_ServiceDescriptor* service_descriptor, mqtt_connection_params_t* connection_params);
iot_agent_status_t iot_agent_mqtt_connect_custom(const nxp_iot_ServiceDescriptor* service_descriptor, mqtt_connection_params_t* connection_params);
iot_agent_status_t iot_agent_mqtt_test(const nxp_iot_ServiceDescriptor* service_descriptor, mqtt_connection_params_t* connection_params);
iot_agent_status_t write_service_configuration_aws(const nxp_iot_ServiceDescriptor* service_descriptor,
    const char* filename, const char* certificate_filename, const char* keyref_filename, const char* server_cert_filename);
iot_agent_status_t write_service_configuration_azure(const nxp_iot_ServiceDescriptor* service_descriptor,
    const char* filename, const char* certificate_filename, const char* keyref_filename, const char* server_cert_filename);
iot_agent_status_t write_service_configuration_custom(const nxp_iot_ServiceDescriptor* service_descriptor,
    const char* filename, const char* certificate_filename, const char* keyref_filename, const char* server_cert_filename);
iot_agent_status_t write_service_metadata(const nxp_iot_ServiceDescriptor* service_descriptor,
    const char* filename);
iot_agent_status_t write_service_configuration(const nxp_iot_ServiceDescriptor* service_descriptor,
    char *filename, char* certificate_filename, const char* keyref_filename, const char* server_cert_filename);


#define JSMN_TOKENS_SIZE 50U
iot_agent_status_t get_value_from_tag(char *js, const char * key, char * value)
{
    jsmn_parser p;
    jsmntok_t tokens[JSMN_TOKENS_SIZE]; /* We expect no more than 50 JSON tokens */
    jsmn_init(&p);
    int count = jsmn_parse(&p, js, strlen(js), tokens, JSMN_TOKENS_SIZE);
    for (int i = 1; i < count; i += 2)
    {
        jsmntok_t *t = &tokens[i];
        char *tag = js + t->start;
        if (!memcmp(tag, key, (size_t)(t->end - t->start)))
        {
            t = &tokens[i + 1];
            memcpy(value, js + t->start, (size_t)(t->end - t->start));
            value[t->end - t->start] = '\0';
            return IOT_AGENT_SUCCESS;
        }
    }
    return IOT_AGENT_FAILURE;
}

void delivered(void *context, MQTTClient_deliveryToken dt)
{
    (void)(context);
    LOG_I("Message with token value %d delivery confirmed\n", dt);
    deliveredtoken = dt;
}

void connlost(void *context, char *cause)
{
    (void)(context);
    LOG_E("\nConnection lost\n");
    LOG_E("     cause: %s\n", cause);
}

int msgarrvd(void *context, char *topicName, int topicLen, MQTTClient_message *message)
{
    (void)(context);
    (void)(topicLen);

    char *payload = malloc((size_t)message->payloadlen + 1U);
    if (payload == NULL)
    {
        return 0;
    }
    memcpy(payload, message->payload, (size_t)message->payloadlen);
    payload[message->payloadlen] = '\0';

    LOG_I("Message arrived\n");
    LOG_I("     topic: %s\n", topicName);
    LOG_I("   message: %s", payload);

    free(payload);
    MQTTClient_freeMessage(&message);
    MQTTClient_free(topicName);
    return 1;
}

int azure_callback(void *context, char *topicName, int topicLen, MQTTClient_message *message)
{
    (void)(context);
    (void)(topicLen);
    char opid[256] = {0};
    char status[64] = {0};

    char *payload = malloc((size_t)message->payloadlen + 1U);
    if (payload == NULL)
    {
        return 0;
    }
    memcpy(payload, message->payload, (size_t)message->payloadlen);
    payload[message->payloadlen] = '\0';

    LOG_I("Message arrived\n");
    LOG_I("     topic: %s\n", topicName);
    LOG_I("   message: %s", payload);

    get_value_from_tag(payload, "operationId", opid);
    get_value_from_tag(payload, "status", status);

    mqtt_azure_params_t* context_cb = (mqtt_azure_params_t*)context;
    LOG_I("reading opid from context: [%s]", context_cb->operationId);

    if (strcmp(status, "assigning") == 0)
    {
        LOG_I("Device State is now ASSIGNING");
        strcpy(context_cb->operationId, IOT_AGENT_MQTT_OPID_TOPIC_AZURE);
        strcat(context_cb->operationId, opid);

        context_cb->state = ASSIGNING;
    }
    else if (strcmp(status, "assigned") == 0)
    {
        LOG_I("Device State is now ASSIGNED");

        get_value_from_tag(payload, "assignedHub", context_cb->assignedHub);
        get_value_from_tag(payload, "deviceId", context_cb->deviceId);

        context_cb->state = ASSIGNED;
    }

    free(payload);

    MQTTClient_freeMessage(&message);
    MQTTClient_free(topicName);
    return 1;
}

iot_agent_status_t connect_and_publish_message(mqtt_connection_params_t* connection_params)
{
    iot_agent_status_t agent_status = IOT_AGENT_FAILURE;
    MQTTClient_connectOptions conn_opts = MQTTClient_connectOptions_initializer;
    MQTTClient_SSLOptions sslopts = MQTTClient_SSLOptions_initializer;
    MQTTClient_message pubmsg = MQTTClient_message_initializer;
    MQTTClient_deliveryToken token = { 0 };
    MQTTClient client = { 0 };
    int rc;
    size_t retry = 0U;

    rc = MQTTClient_create(&client, connection_params->address,
        connection_params->clientid, MQTTCLIENT_PERSISTENCE_NONE, NULL);
    ASSERT_OR_EXIT_MSG(rc == MQTTCLIENT_SUCCESS, "MQTTClient_create Failed, return code [%d]", rc);

    conn_opts.keepAliveInterval = 60;
    conn_opts.cleansession = 1;
    conn_opts.reliable = 0;
    conn_opts.username = connection_params->username;
    conn_opts.password = NULL;

    sslopts.enableServerCertAuth = 0;
    sslopts.trustStore = connection_params->rootpath;
    sslopts.privateKey = connection_params->keypath;
    sslopts.keyStore = connection_params->devcert;
    conn_opts.ssl = &sslopts;

    MQTTClient_setCallbacks(client, NULL, connlost, msgarrvd, delivered);

    while (
        ((rc = MQTTClient_connect(client, &conn_opts)) != MQTTCLIENT_SUCCESS)) {
        if (rc == 3 && retry++ < 3U) { // connection refused: server unavailable
            SLEEP_SEC(1U);
        }
        else {
            IOT_AGENT_ERROR("Failed to connect, return code %d\n", rc);
            goto exit;
        }
    }

    pubmsg.payload = connection_params->payload;
    pubmsg.payloadlen = (int)strlen(connection_params->payload);
    pubmsg.qos = 1;
    pubmsg.retained = 0;
    for (int i = 0; i < 3; i++)
    {
        rc = MQTTClient_publishMessage(client, connection_params->topic, &pubmsg, &token);
        ASSERT_OR_EXIT_MSG(rc == MQTTCLIENT_SUCCESS, "MQTTClient_publishMessage Failed, return code [%d]", rc);
        IOT_AGENT_INFO("Message successfully published");
    }
    agent_status = IOT_AGENT_SUCCESS;
exit:
    MQTTClient_disconnect(client, 10000);
    MQTTClient_destroy(&client);
    return agent_status;
}

iot_agent_status_t iot_agent_mqtt_connect_aws(const nxp_iot_ServiceDescriptor* service_descriptor, mqtt_connection_params_t* connection_params)
{
    iot_agent_status_t agent_status;
    int n = snprintf(connection_params->address,
        sizeof(connection_params->address),
        "ssl://%s:8883",
        service_descriptor->hostname);
    if (n > (int)sizeof(connection_params->address)) {
        LOG_E("Error, buffer for storing URL was too small.\n");
        return IOT_AGENT_FAILURE;
    }

    strcpy(connection_params->username, IOT_AGENT_MQTT_USERNAME_AWS);
    strcpy(connection_params->topic, IOT_AGENT_MQTT_TOPIC_AWS);
    connection_params->clientid = service_descriptor->client_id;
    connection_params->payload = IOT_AGENT_MQTT_PAYLOAD;

    IOT_AGENT_INFO("\nConnecting to AWS service: %s", service_descriptor->client_id)
    agent_status = connect_and_publish_message(connection_params);
    AGENT_SUCCESS_OR_EXIT();
exit:
    return agent_status;

}

iot_agent_status_t iot_agent_mqtt_register_azure(mqtt_connection_params_t* connection_params, mqtt_azure_params_t* azure_params)
{
    iot_agent_status_t agent_status = IOT_AGENT_FAILURE;
    MQTTClient client = { 0 };
    MQTTClient_connectOptions conn_opts = MQTTClient_connectOptions_initializer;
    MQTTClient_message pubmsg = MQTTClient_message_initializer;
    MQTTClient_deliveryToken token = { 0 };
    int rc = -1;
    uint16_t maxWaiting = 0U;
    size_t retry = 3U;

    if ((rc = MQTTClient_create(&client, connection_params->address, connection_params->clientid,
        MQTTCLIENT_PERSISTENCE_NONE, NULL)) != MQTTCLIENT_SUCCESS)
    {
        IOT_AGENT_ERROR("MQTTClient_create Failed, return code %d\n", rc);

    }

    conn_opts.keepAliveInterval = 60;
    conn_opts.cleansession = 1;
    conn_opts.reliable = 0;
    conn_opts.username = connection_params->username;
    conn_opts.password = NULL;
    MQTTClient_SSLOptions sslopts = MQTTClient_SSLOptions_initializer;

    sslopts.enableServerCertAuth = 0;
    sslopts.trustStore = connection_params->rootpath;
    sslopts.privateKey = connection_params->keypath;
    sslopts.keyStore = connection_params->devcert;
    conn_opts.ssl = &sslopts;

    MQTTClient_setCallbacks(client, azure_params, connlost, azure_callback, delivered);

    while (
        ((rc = MQTTClient_connect(client, &conn_opts)) != MQTTCLIENT_SUCCESS) && retry--) {
        if (rc == 3) { // connection refused: server unavailable
            SLEEP_SEC(1U);
        }
        else {
			EXIT_STATUS_MSG(IOT_AGENT_FAILURE, "Failed to connect, return code %d\n", rc);
        }
    }

    rc = MQTTClient_subscribe(client, IOT_AGENT_MQTT_SUBSCRIBE_TOPIC_AZURE, 1);
    ASSERT_OR_EXIT_MSG(rc == MQTTCLIENT_SUCCESS, "MQTTClient_subscribe Failed, return code [%d]", rc);

    azure_params->state = NOT_ASSIGNED;
    strcpy(azure_params->operationId, "testing");
    pubmsg.qos = 1;

    rc = MQTTClient_publishMessage(client, IOT_AGENT_MQTT_REGISTRATION_TOPIC_AZURE, &pubmsg, &token);
    ASSERT_OR_EXIT_MSG(rc == MQTTCLIENT_SUCCESS, "MQTTClient_publishMessage while registering failed, return code [%d]", rc);

    while (azure_params->state != ASSIGNING && maxWaiting < 10U)
    {
        SLEEP_SEC(1U);
        maxWaiting++;
    }

    maxWaiting = 0U;
    while (azure_params->state != ASSIGNED && maxWaiting < 10U)
    {
        SLEEP_SEC(1U * (maxWaiting + 1U));
        rc = MQTTClient_publishMessage(client, azure_params->operationId, &pubmsg, &token);
        ASSERT_OR_EXIT_MSG(rc == MQTTCLIENT_SUCCESS, "MQTTClient_publishMessage while assigning failed, return code [%d]", rc);
        maxWaiting++;
    }

    if (azure_params->state == ASSIGNED)
    {
        IOT_AGENT_INFO("\nAzure registration is successful for [%s]", azure_params->deviceId)
            agent_status = IOT_AGENT_SUCCESS;
    }

    LOG_I("Disconnect MQTT connection...");

exit:
    MQTTClient_disconnect(client, 10000);
    MQTTClient_destroy(&client);
    return agent_status;
}

iot_agent_status_t iot_agent_mqtt_connect_azure(mqtt_connection_params_t* connection_params, mqtt_azure_params_t* azure_params)
{
    iot_agent_status_t agent_status;
    int m = snprintf(connection_params->address,
        sizeof(connection_params->address),
        "ssl://%s:8883",
        azure_params->assignedHub);
    int n = snprintf(connection_params->username,
        sizeof(connection_params->username),
        "%s/%s/?api-version=2018-06-30",
        azure_params->assignedHub,
        azure_params->deviceId);

    int o = snprintf(connection_params->topic,
        sizeof(connection_params->topic),
        "devices/%s/messages/events/",
        azure_params->deviceId);
    if (m > (int)sizeof(connection_params->address) || n > (int)sizeof(connection_params->username) || o > (int)sizeof(connection_params->topic)) {
        LOG_E("Error, buffer for storing address/username was too small.\n");
        return IOT_AGENT_FAILURE;
    }

    connection_params->clientid = azure_params->deviceId;
    connection_params->payload = IOT_AGENT_MQTT_PAYLOAD;
    IOT_AGENT_INFO("Connecting to Azure service: %s", azure_params->deviceId)
    agent_status = connect_and_publish_message(connection_params);
    return agent_status;
}

iot_agent_status_t iot_agent_mqtt_register_and_connect_azure(const nxp_iot_ServiceDescriptor* service_descriptor, mqtt_connection_params_t* connection_params)
{
    iot_agent_status_t agent_status;
    mqtt_azure_params_t azure_params = { 0 };
    int m = snprintf(connection_params->address,
        sizeof(connection_params->address),
        "ssl://%s:8883",
        service_descriptor->azure_global_device_endpoint);

    int n = snprintf(connection_params->username,
        sizeof(connection_params->username),
        "%s/registrations/%s/api-version=2018-11-01&ClientVersion=1.4.0",
        service_descriptor->azure_id_scope,
        service_descriptor->azure_registration_id);

    if (m > (int)sizeof(connection_params->address) || n > (int)sizeof(connection_params->username)) {
        LOG_E("Error, buffer for storing hubname/username was too small.\n");
        return IOT_AGENT_FAILURE;
    }
    connection_params->clientid = service_descriptor->azure_registration_id;
    connection_params->payload = "HelloMessage";

    agent_status = iot_agent_mqtt_register_azure(connection_params, &azure_params);
    AGENT_SUCCESS_OR_EXIT();
    agent_status = iot_agent_mqtt_connect_azure(connection_params, &azure_params);
    AGENT_SUCCESS_OR_EXIT();
exit:
    return agent_status;
}

iot_agent_status_t iot_agent_mqtt_connect_custom(const nxp_iot_ServiceDescriptor* service_descriptor, mqtt_connection_params_t* connection_params)
{
    iot_agent_status_t agent_status;
    int n = snprintf(connection_params->address,
        sizeof(connection_params->address),
        "ssl://%s:8883",
        service_descriptor->hostname);
    if (n > (int)sizeof(connection_params->address)) {
        LOG_E("Error, buffer for storing URL was too small.\n");
        return IOT_AGENT_FAILURE;
    }
    strcpy(connection_params->username, IOT_AGENT_MQTT_USERNAME_CUSTOM);
    strcpy(connection_params->topic, IOT_AGENT_MQTT_TOPIC_CUSTOM);
    connection_params->clientid = (service_descriptor->client_id != NULL) ? service_descriptor->client_id : "";
    connection_params->payload = IOT_AGENT_MQTT_PAYLOAD;

    IOT_AGENT_INFO("\nConnecting to custome service: %s", service_descriptor->hostname)
    agent_status = connect_and_publish_message(connection_params);
    AGENT_SUCCESS_OR_EXIT();
exit:
    return agent_status;
}

int network_openssl_engine_session_connect_mqtt() {

    int network_status = NETWORK_STATUS_OK;
    ENGINE *e = ENGINE_by_id(NETWORK_OPENSSL_ENGINE_ID);
    NETWORK_ASSERT_OR_EXIT_MSG(e != NULL, "Error finding OpenSSL Engine by id (id = %s)\n", NETWORK_OPENSSL_ENGINE_ID);

    // NOTE: Open engine connection to SE via Engine control interface
    LOG_I("Open connection to secure element through Engine control interface (Engine=%s).\n", NETWORK_OPENSSL_ENGINE_ID);
    ENGINE_ctrl(e, ENGINE_CMD_BASE + 1, 0, NULL, NULL);

exit:
    ENGINE_free(e);
    return network_status;
}

int network_openssl_engine_session_disconnect_mqtt() {
    int network_status = NETWORK_STATUS_OK;

    ENGINE *e = ENGINE_by_id(NETWORK_OPENSSL_ENGINE_ID);
    NETWORK_ASSERT_OR_EXIT_MSG(e != NULL, "Error finding OpenSSL Engine by id (id = %s)\n", NETWORK_OPENSSL_ENGINE_ID);

    LOG_I("Close connection to secure element through Engine control interface (Engine=%s).\n", NETWORK_OPENSSL_ENGINE_ID);
    ENGINE_ctrl(e, ENGINE_CMD_BASE + 2, 0, NULL, NULL);

exit:
    ENGINE_free(e);
    return network_status;
}

iot_agent_status_t iot_agent_mqtt_test(const nxp_iot_ServiceDescriptor* service_descriptor, mqtt_connection_params_t* connection_params)
{
    iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
    int network_status = 0;

    network_status = network_openssl_engine_session_connect_mqtt();
    ASSERT_OR_EXIT_MSG(network_status == NETWORK_STATUS_OK, "network_openssl_engine_session_connect failed with 0x%08x.", network_status);
    switch (service_descriptor->service_type)
    {
    case nxp_iot_ServiceType_AWSSERVICE:
        agent_status = iot_agent_mqtt_connect_aws(service_descriptor, connection_params);
        break;
    case nxp_iot_ServiceType_AZURESERVICE:
        agent_status = iot_agent_mqtt_register_and_connect_azure(service_descriptor, connection_params);
        break;
    case nxp_iot_ServiceType_CUSTOMSERVICE:
        agent_status = iot_agent_mqtt_connect_custom(service_descriptor, connection_params);
        break;
    default:
        LOG_E("Invalid service type\n");
        break;
    }
    network_status = network_openssl_engine_session_disconnect_mqtt();
    ASSERT_OR_EXIT_MSG(network_status == NETWORK_STATUS_OK, "network_openssl_engine_session_connect failed with 0x%08x.", network_status);
exit:
    return agent_status;
}
#endif //IOT_AGENT_MQTT_CONNECTION_DEMO_ENABLE

void write_error_logs(const char* message)
{
#if (!AX_EMBEDDED)
    FILE* fp = fopen("output\\errors.log", "a");
    if (fp != NULL) {
        fprintf(fp, "Error: %s \n", message);
        fclose(fp);
    }
#endif
}

void delete_old_service_files(const char* output_directory)
{
    DIR *dir;
    struct dirent *file;
    char filepath[256];
    if ((dir = opendir(output_directory)) != NULL)
    {
        while ((file = readdir(dir)) != NULL)
        {
            if (!strcmp(file->d_name, ".") || !strcmp(file->d_name, ".."))
            {
                continue;
            }
            sprintf(filepath, "%s/%s", output_directory, file->d_name);
            if (remove(filepath) != 0)
            {
                closedir(dir);
                return;
            };
        }
        closedir(dir);
        return;
    }
	else if (errno == ENOENT) 
	{
		// do not print anything if directory doesn't exist
		return;
	}
    else
    {
        /* could not open directory */
        perror("");
        return;
    }
}

void delete_old_service_files_folders(const char* output_directory)
{
    DIR *dir;
    struct dirent *file;
    char subdir[256];
    if ((dir = opendir(output_directory)) != NULL)
    {
        while ((file = readdir(dir)) != NULL)
        {
            if (!strcmp(file->d_name, ".") || !strcmp(file->d_name, ".."))
            {
                continue;
            }
            sprintf(subdir, "%s/%s", output_directory, file->d_name);
            delete_old_service_files(subdir);
        }
        delete_old_service_files(output_directory);
        closedir(dir);
        return;
    }
	else if (errno == ENOENT) 
	{
		// do not print anything if directory doesn't exist
		return;
	}
    else
    {
        /* could not open directory */
        perror("");
        return;
    }
}

iot_agent_status_t write_service_configuration_aws(const nxp_iot_ServiceDescriptor* service_descriptor,
    const char* filename, const char* certificate_filename, const char* keyref_filename, const char* server_cert_filename)
{
    iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
    const char* protocol = NULL;
    FILE* fp = NULL;

    ASSERT_OR_EXIT_MSG(service_descriptor->hostname != NULL, "Missing hostname.");
    ASSERT_OR_EXIT_MSG(service_descriptor->client_id != NULL, "Missing client_id.");
    agent_status = iot_agent_service_get_protocol_of_service_as_string(service_descriptor, &protocol);
    AGENT_SUCCESS_OR_EXIT();
    fp = fopen(filename, "w");
    ASSERT_OR_EXIT_MSG(fp != NULL, "Error opening file");

    fprintf(fp, "{\n");
    fprintf(fp, "  \"endpoint\": \"%s\",\n", service_descriptor->hostname);
    fprintf(fp, "  \"protocol\": \"%s\",\n", protocol);
    fprintf(fp, "  \"port\": %d,\n", service_descriptor->port);
    fprintf(fp, "  \"mqtt_port\": 8883,\n");
    fprintf(fp, "  \"https_port\": 443,\n");
    fprintf(fp, "  \"greengrass_discovery_port\": 8443,\n");
    fprintf(fp, "  \"root_ca_relative_path\": \"%s\",\n", server_cert_filename);
    fprintf(fp, "  \"device_certificate_relative_path\": \"%s\",\n", certificate_filename);
    fprintf(fp, "  \"device_private_key_relative_path\": \"%s\",\n", keyref_filename);
    fprintf(fp, "  \"tls_handshake_timeout_msecs\": 60000,\n");
    fprintf(fp, "  \"tls_read_timeout_msecs\": 2000,\n");
    fprintf(fp, "  \"tls_write_timeout_msecs\": 2000,\n");
    fprintf(fp, "  \"aws_region\": \"\",\n");
    fprintf(fp, "  \"aws_access_key_id\": \"\",\n");
    fprintf(fp, "  \"aws_secret_access_key\": \"\",\n");
    fprintf(fp, "  \"aws_session_token\": \"\",\n");
    fprintf(fp, "  \"client_id\": \"%s\",\n", service_descriptor->client_id);
    fprintf(fp, "  \"thing_name\": \"CppSDKTesting\",\n");
    fprintf(fp, "  \"is_clean_session\": true,\n");
    fprintf(fp, "  \"mqtt_command_timeout_msecs\": %d,\n", service_descriptor->timeout_ms);
    fprintf(fp, "  \"keepalive_interval_secs\": 600,\n");
    fprintf(fp, "  \"minimum_reconnect_interval_secs\": 1,\n");
    fprintf(fp, "  \"maximum_reconnect_interval_secs\": 128,\n");
    fprintf(fp, "  \"maximum_acks_to_wait_for\": 32,\n");
    fprintf(fp, "  \"action_processing_rate_hz\": 5,\n");
    fprintf(fp, "  \"maximum_outgoing_action_queue_length\": 32,\n");
    fprintf(fp, "  \"discover_action_timeout_msecs\": 300000\n");
    fprintf(fp, "}");
    fclose(fp);
exit:
    return agent_status;
}

iot_agent_status_t write_service_configuration_azure(const nxp_iot_ServiceDescriptor* service_descriptor,
    const char* filename, const char* certificate_filename, const char* keyref_filename, const char* server_cert_filename)
{
    iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
    FILE* fp = NULL;

    ASSERT_OR_EXIT_MSG(service_descriptor->azure_id_scope != NULL, "Missing azure_id_scope.");
    ASSERT_OR_EXIT_MSG(service_descriptor->azure_global_device_endpoint != NULL, "Missing azure_global_device_endpoint.");
    ASSERT_OR_EXIT_MSG(service_descriptor->azure_registration_id != NULL, "Missing azure_registration_id.");

    fp = fopen(filename, "w");
    ASSERT_OR_EXIT_MSG(fp != NULL, "Error opening file");
    fprintf(fp, "{\n");
    fprintf(fp, "  \"id_scope\": \"%s\",\n", service_descriptor->azure_id_scope);
    fprintf(fp, "  \"global_device_endpoint\": \"%s\",\n", service_descriptor->azure_global_device_endpoint);
    fprintf(fp, "  \"registration_id\": \"%s\",\n", service_descriptor->azure_registration_id);
    fprintf(fp, "  \"devcert\": \"%s\",\n", certificate_filename);
    fprintf(fp, "  \"keypath\": \"%s\",\n", keyref_filename);
    fprintf(fp, "  \"rootpath\": \"%s\",\n", server_cert_filename);
    fprintf(fp, "}");
    fclose(fp);

exit:
    return agent_status;
}

iot_agent_status_t write_service_configuration_custom(const nxp_iot_ServiceDescriptor* service_descriptor,
    const char* filename, const char* certificate_filename, const char* keyref_filename, const char* server_cert_filename)
{
    iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
    const char* protocol = NULL;
    const char* hostname = "empty";
    FILE* fp = NULL;

    agent_status = iot_agent_service_get_protocol_of_service_as_string(service_descriptor, &protocol);
    AGENT_SUCCESS_OR_EXIT();

    if (service_descriptor->hostname != NULL)
        hostname = service_descriptor->hostname;

    fp = fopen(filename, "w");
    ASSERT_OR_EXIT_MSG(fp != NULL, "Error opening file");
    fprintf(fp, "{\n");
    fprintf(fp, "  \"hostname\": \"%s\",\n", hostname);
    fprintf(fp, "  \"username\": \"use-token-auth\",\n");
    fprintf(fp, "  \"protocol\": \"%s\",\n", protocol);
    fprintf(fp, "  \"port\": \"%d\",\n", service_descriptor->port);
    fprintf(fp, "  \"devcert\": \"%s\",\n", certificate_filename);
    fprintf(fp, "  \"keypath\": \"%s\",\n", keyref_filename);
    fprintf(fp, "  \"payload\": \"HelloMessage\",\n");
    fprintf(fp, "  \"topic\": \"iot-2/evt/status/fmt/string\",\n");
    fprintf(fp, "  \"rootpath\": \"%s\",\n", server_cert_filename);
    fprintf(fp, "}");
    fclose(fp);

exit:
    return agent_status;
}

iot_agent_status_t write_service_metadata(const nxp_iot_ServiceDescriptor* service_descriptor,
    const char* filename)
{
    iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
    const char * metadata = "{}";
    FILE* fp = NULL;

    if (service_descriptor->customer_metadata_json != NULL) {
        metadata = service_descriptor->customer_metadata_json;
    }

    fp = fopen(filename, "w");
    ASSERT_OR_EXIT_MSG(fp != NULL, "Error opening file");
    fprintf(fp, "%s\n", metadata);
    fclose(fp);
exit:
    return agent_status;
}

iot_agent_status_t write_service_configuration(const nxp_iot_ServiceDescriptor* service_descriptor,
    char *filename, char* certificate_filename, const char* keyref_filename, const char* server_cert_filename)
{
    iot_agent_status_t agent_status = IOT_AGENT_FAILURE;
    ASSERT_OR_EXIT_MSG(service_descriptor->has_service_type, "Missing service type");

    switch (service_descriptor->service_type)
    {
    case nxp_iot_ServiceType_AWSSERVICE:
        return write_service_configuration_aws(service_descriptor, filename, certificate_filename, keyref_filename, server_cert_filename);
    case nxp_iot_ServiceType_AZURESERVICE:
        return write_service_configuration_azure(service_descriptor, filename, certificate_filename, keyref_filename, server_cert_filename);
        //TODO: Currently config files for Google and IBM services are being written same as custom service
    case nxp_iot_ServiceType_GOOGLESERVICE:
    case nxp_iot_ServiceType_IBMSERVICE:
    case nxp_iot_ServiceType_CUSTOMSERVICE:
        return write_service_configuration_custom(service_descriptor, filename, certificate_filename, keyref_filename, server_cert_filename);
    default:
        IOT_AGENT_ERROR("Unknown service type");
        break;
    }
exit:
    return agent_status;
}


// doc: trigger MQTT connection paho - start
iot_agent_status_t iot_agent_verify_mqtt_connection_for_service(iot_agent_context_t* iot_agent_context, const nxp_iot_ServiceDescriptor* service_descriptor)
{
	iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
	int mkdir_check = 0;

#if IOT_AGENT_MQTT_CONNECTION_TEST_ENABLE
	mqtt_connection_params_t connection_params = { 0 };
	iot_agent_status_t mqtt_status = IOT_AGENT_SUCCESS;
#endif
	//write to files

	char config_filename[256];
	char certificate_filename[256];
	char keyref_filename[256];
	char server_cert_filename[256];
	char metadata_filename[256];

	const char* service_type_str;
	char service_dir[64];

	uint32_t keystore_id = service_descriptor->client_key_sss_ref.endpoint_id;
	iot_agent_keystore_t* keystore = NULL;
	agent_status = iot_agent_get_keystore_by_id(iot_agent_context, keystore_id, &keystore);
	AGENT_SUCCESS_OR_EXIT();

    agent_status = iot_agent_keystore_open_session(keystore);
    AGENT_SUCCESS_OR_EXIT();

	agent_status = iot_agent_service_get_service_type_as_string(service_descriptor, &service_type_str);
	AGENT_SUCCESS_OR_EXIT();

	if (ACCESS(goutput_directory, R_OK) != 0)
	{
		mkdir_check = DO_MKDIR(goutput_directory);
		ASSERT_OR_EXIT(mkdir_check == 0);
	}

	sprintf(service_dir, "%s%c%s%c", goutput_directory, path_separator, service_type_str, path_separator);
	if (ACCESS(service_dir, R_OK) != 0)
	{
		mkdir_check = DO_MKDIR(service_dir);
		ASSERT_OR_EXIT(mkdir_check == 0);
	}

	sprintf(config_filename, "%s" SERVICE_CONFIGURATION_PATTERN, service_dir, service_descriptor->identifier);
	sprintf(metadata_filename, "%s" SERVICE_METADATA_PATTERN, service_dir, service_descriptor->identifier);
	sprintf(keyref_filename, "%s" SERVICE_KEYREF_PATTERN, service_dir, service_descriptor->identifier);
	sprintf(certificate_filename, "%s" SERVICE_CERTIFICATE_PATTERN, service_dir, service_descriptor->identifier);
	sprintf(server_cert_filename, "%s" SERVICE_SERVER_CERT_PATTERN, service_dir, service_type_str, service_descriptor->identifier);

	//create service files
	char relative_certificate_filename[128];
	char relative_keyref_filename[128];
	char relative_server_cert_filename[128];
	sprintf(relative_certificate_filename, SERVICE_CERTIFICATE_PATTERN, service_descriptor->identifier);
	sprintf(relative_keyref_filename, SERVICE_KEYREF_PATTERN, service_descriptor->identifier);
	sprintf(relative_server_cert_filename, SERVICE_SERVER_CERT_PATTERN, service_type_str, service_descriptor->identifier);

	if (IOT_AGENT_SUCCESS != write_service_configuration(service_descriptor, config_filename,
		relative_certificate_filename, relative_keyref_filename, relative_server_cert_filename))
	{
		write_error_logs(config_filename);
	}
	else
	{
		LOG_D("Created service configuration file [%s]", config_filename);
	}

	if (IOT_AGENT_SUCCESS != write_service_metadata(service_descriptor, metadata_filename))
	{
		write_error_logs(metadata_filename);
	}
	else
	{
		LOG_D("Created metadata file [%s]", metadata_filename);
	}

	if (service_descriptor->server_certificate != NULL) {
		if (IOT_AGENT_SUCCESS != iot_agent_utils_write_certificate_pem(service_descriptor->server_certificate->bytes,
			(size_t)service_descriptor->server_certificate->size, server_cert_filename))
		{
			write_error_logs(server_cert_filename);
		}
		else
		{
			LOG_D("Created server root certificate file [%s]", server_cert_filename);
		}
	}

	if (service_descriptor->client_certificate != NULL) {
		if (IOT_AGENT_SUCCESS != iot_agent_utils_write_certificate_pem(service_descriptor->client_certificate->bytes,
			(size_t)service_descriptor->client_certificate->size, certificate_filename))
		{
			write_error_logs(certificate_filename);
		}
		else
		{
			LOG_D("Created service client certificate file [%s]", certificate_filename);
		}
	}

	if (IOT_AGENT_SUCCESS != iot_agent_utils_write_key_ref_service_pem(iot_agent_context, keyref_filename))
	{
		write_error_logs(keyref_filename);
	}
	else
	{
		LOG_D("Created service keyref file [%s]", keyref_filename);
	}
	//write to files - end

#if IOT_AGENT_MQTT_CONNECTION_TEST_ENABLE
	iot_agent_keystore_close_session(keystore);

	connection_params.keypath = keyref_filename;
	connection_params.devcert = certificate_filename;
	connection_params.rootpath = server_cert_filename;
	mqtt_status = iot_agent_mqtt_test(service_descriptor, &connection_params);

	agent_status = iot_agent_keystore_open_session(keystore);
	AGENT_SUCCESS_OR_EXIT();
#endif
exit:
	if (mqtt_status != IOT_AGENT_SUCCESS) {
		return mqtt_status;
	}
	return agent_status;
}

iot_agent_status_t iot_agent_verify_mqtt_connection(iot_agent_context_t* iot_agent_context)
{
    iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
    size_t number_of_services = 0U;
	nxp_iot_ServiceDescriptor service_descriptor = nxp_iot_ServiceDescriptor_init_default;

    number_of_services = iot_agent_get_number_of_services(iot_agent_context);
	delete_old_service_files_folders(goutput_directory);
    AGENT_SUCCESS_OR_EXIT();

    for (size_t i = 0U; i < number_of_services; i++)
    {
		agent_status = iot_agent_select_service_by_index(iot_agent_context, i, &service_descriptor);
		AGENT_SUCCESS_OR_EXIT();

		agent_status = iot_agent_verify_mqtt_connection_for_service(iot_agent_context, &service_descriptor);
		AGENT_SUCCESS_OR_EXIT();
	}
exit:
	iot_agent_free_service_descriptor(&service_descriptor);
    return agent_status;
}


// doc: trigger MQTT connection paho - end

iot_agent_status_t iot_agent_cleanup_mqtt_config_files()
{
	delete_old_service_files_folders(goutput_directory);
	return IOT_AGENT_SUCCESS;
}

#if	(SSS_HAVE_HOSTCRYPTO_OPENSSL)
iot_agent_status_t iot_agent_verify_mqtt_connection_cos_over_rtp(iot_agent_context_t* iot_agent_context, const nxp_iot_ServiceDescriptor* service_descriptor)
{
	iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
	int mkdir_check = 0;

#if IOT_AGENT_MQTT_CONNECTION_TEST_ENABLE
	mqtt_connection_params_t connection_params = { 0 };
	iot_agent_status_t mqtt_status = IOT_AGENT_SUCCESS;
#endif
	//write to files

	char config_filename[256];
	char certificate_filename[256];
	char keyref_filename[256];
	char server_cert_filename[256];
	char metadata_filename[256];

	const char* service_type_str;
	char service_dir[64];

	uint32_t keystore_id = service_descriptor->client_key_sss_ref.endpoint_id;
	iot_agent_keystore_t* keystore = NULL;
	agent_status = iot_agent_get_keystore_by_id(iot_agent_context, keystore_id, &keystore);
	AGENT_SUCCESS_OR_EXIT();

	agent_status = iot_agent_keystore_open_session(keystore);
	AGENT_SUCCESS_OR_EXIT();

	agent_status = iot_agent_service_get_service_type_as_string(service_descriptor, &service_type_str);
	AGENT_SUCCESS_OR_EXIT();

	if (ACCESS(goutput_directory_rtp, R_OK) != 0)
	{
		mkdir_check = DO_MKDIR(goutput_directory_rtp);
		ASSERT_OR_EXIT(mkdir_check == 0);
	}

	sprintf(service_dir, "%s%c%s%c", goutput_directory_rtp, path_separator, service_type_str, path_separator);
	if (ACCESS(service_dir, R_OK) != 0)
	{
		mkdir_check = DO_MKDIR(service_dir);
		ASSERT_OR_EXIT(mkdir_check == 0);
	}

	sprintf(config_filename, "%s" SERVICE_CONFIGURATION_PATTERN, service_dir, service_descriptor->identifier);
	sprintf(metadata_filename, "%s" SERVICE_METADATA_PATTERN, service_dir, service_descriptor->identifier);
	sprintf(keyref_filename, "%s" SERVICE_KEYREF_PATTERN, service_dir, service_descriptor->identifier);
	sprintf(certificate_filename, "%s" SERVICE_CERTIFICATE_PATTERN, service_dir, service_descriptor->identifier);
	sprintf(server_cert_filename, "%s" SERVICE_SERVER_CERT_PATTERN, service_dir, service_type_str, service_descriptor->identifier);

	//create service files
	char relative_certificate_filename[128];
	char relative_keyref_filename[128];
	char relative_server_cert_filename[128];
	sprintf(relative_certificate_filename, SERVICE_CERTIFICATE_PATTERN, service_descriptor->identifier);
	sprintf(relative_keyref_filename, SERVICE_KEYREF_PATTERN, service_descriptor->identifier);
	sprintf(relative_server_cert_filename, SERVICE_SERVER_CERT_PATTERN, service_type_str, service_descriptor->identifier);

	if (IOT_AGENT_SUCCESS != write_service_configuration(service_descriptor, config_filename,
		relative_certificate_filename, relative_keyref_filename, relative_server_cert_filename))
	{
		write_error_logs(config_filename);
	}
	else
	{
		LOG_D("Created service configuration file [%s]", config_filename);
	}

	if (IOT_AGENT_SUCCESS != write_service_metadata(service_descriptor, metadata_filename))
	{
		write_error_logs(metadata_filename);
	}
	else
	{
		LOG_D("Created metadata file [%s]", metadata_filename);
	}

	if (service_descriptor->server_certificate != NULL) {
		if (IOT_AGENT_SUCCESS != iot_agent_utils_write_certificate_pem(service_descriptor->server_certificate->bytes,
			(size_t)service_descriptor->server_certificate->size, server_cert_filename))
		{
			write_error_logs(server_cert_filename);
		}
		else
		{
			LOG_D("Created server root certificate file [%s]", server_cert_filename);
		}
	}

	if (service_descriptor->has_client_certificate_sss_ref == true) {
		if (IOT_AGENT_SUCCESS != iot_agent_utils_write_certificate_pem_cos_over_rtp(iot_agent_context, service_descriptor, certificate_filename))
		{
			write_error_logs(certificate_filename);
		}
		else
		{
			LOG_D("Created service client certificate file [%s]", certificate_filename);
		}
	}

	if (IOT_AGENT_SUCCESS != iot_agent_utils_write_key_ref_pem_cos_over_rtp(iot_agent_context, service_descriptor, keyref_filename))
	{
		write_error_logs(keyref_filename);
	}
	else
	{
		LOG_D("Created service keyref file [%s]", keyref_filename);
	}
	//write to files - end

#if IOT_AGENT_MQTT_CONNECTION_TEST_ENABLE
	iot_agent_keystore_close_session(keystore);

	connection_params.keypath = keyref_filename;
	connection_params.devcert = certificate_filename;
	connection_params.rootpath = server_cert_filename;
	mqtt_status = iot_agent_mqtt_test(service_descriptor, &connection_params);

	agent_status = iot_agent_keystore_open_session(keystore);
	AGENT_SUCCESS_OR_EXIT();
#endif
exit:
	if (mqtt_status != IOT_AGENT_SUCCESS) {
		return mqtt_status;
	}
	return agent_status;
}

iot_agent_status_t iot_agent_cleanup_mqtt_config_files_cos_over_rtp()
{
	delete_old_service_files_folders(goutput_directory_rtp);
	return IOT_AGENT_SUCCESS;
}
#endif

