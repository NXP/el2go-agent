/*
 * Copyright 2024 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifdef __ZEPHYR__
#include <zephyr/kernel.h>
#else
#include "app.h"
#include "FreeRTOS.h"
#include "FreeRTOSConfig.h"
#include "task.h"
#endif

#include "tfm_ns_interface.h"

#include <mbedtls/oid.h>
#include <mbedtls/x509_crt.h>

#include <nxp_iot_agent.h>
#include <nxp_iot_agent_macros.h>
#include <nxp_iot_agent_macros_psa.h>

#include <iot_agent_network.h>
#include <iot_agent_demo_config.h>

#ifdef __ZEPHYR__
#include <iot_agent_mqtt_zephyr.h>
#else
#include <iot_agent_mqtt_freertos.h>
#endif

#define COMMON_NAME_MAX_SIZE 256

#ifdef __ZEPHYR__
#define MQTT_THREAD_STACK_SIZE (1024 * 32)
K_THREAD_STACK_DEFINE(mqtt_thread_stack_area, MQTT_THREAD_STACK_SIZE);
#else
#define MQTT_THREAD_STACK_SIZE (1024 * 8)
#endif

enum Color
{
    BLUE,
    YELLOW,
    RED,
    GREEN
};

static void set_rgb_led(enum Color color)
{
#ifdef __ZEPHYR__
    // TODO: Implement LED API calls
#else
#ifdef HAVE_RGB_LED
    taskENTER_CRITICAL();
    switch (color)
    {
        case BLUE:
            LED_On(RGB_LED_BLUE);
            LED_Off(RGB_LED_RED | RGB_LED_GREEN);
            break;
        case YELLOW:
            LED_On(RGB_LED_RED | RGB_LED_GREEN);
            LED_Off(RGB_LED_BLUE);
            break;
        case RED:
            LED_On(RGB_LED_RED);
            LED_Off(RGB_LED_GREEN | RGB_LED_BLUE);
            break;
        case GREEN:
            LED_On(RGB_LED_GREEN);
            LED_Off(RGB_LED_RED | RGB_LED_BLUE);
            break;
    }
    taskEXIT_CRITICAL();
#endif // HAVE_RGB_LED
#endif
}

static iot_agent_status_t iot_agent_get_oid_value_in_subject(
    uint8_t *cert_buffer, size_t cert_len, char *oid, char *value, size_t max_size)
{
    iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
    mbedtls_x509_crt client_cert    = {0};
    char *oid_name                  = NULL;
    mbedtls_x509_name *oid_ptr;
    size_t len     = 0;
    bool oid_found = false;

    ASSERT_OR_EXIT_MSG(cert_buffer != NULL, "cert_buffer is NULL.");
    ASSERT_OR_EXIT_MSG(oid != NULL, "oid is NULL.");
    ASSERT_OR_EXIT_MSG(value != NULL, "value is NULL.");

    mbedtls_x509_crt_init(&client_cert);

    if (mbedtls_x509_crt_parse_der(&client_cert, cert_buffer, cert_len) != 0)
    {
        EXIT_STATUS_MSG(IOT_AGENT_FAILURE, "Error in loading the client certificate");
    }

    oid_ptr = &client_cert.subject;

    while (oid_ptr != NULL)
    {
        mbedtls_oid_get_attr_short_name((mbedtls_asn1_buf *)oid_ptr, (const char **)&oid_name);
        if (strcmp(oid_name, oid) == 0)
        {
            len = oid_ptr->val.len;
            if (len > max_size)
            {
                EXIT_STATUS_MSG(IOT_AGENT_FAILURE, "Error in loading the client certificate");
            }
            for (size_t i = 0U; i < len; i++)
            {
                ASSERT_OR_EXIT_MSG((oid_ptr->val.p[i] <= INT8_MAX), "Wrapparound in assigning");
                *(value + i) = oid_ptr->val.p[i];
            }
            oid_found = true;
        }

        oid_ptr = oid_ptr->next;
    }

    if (!oid_found)
    {
        EXIT_STATUS_MSG(IOT_AGENT_FAILURE, "Unable to find the OID");
    }
exit:
    mbedtls_x509_crt_free(&client_cert);
    return agent_status;
}

static iot_agent_status_t iot_agent_get_certificate_common_name(const nxp_iot_ServiceDescriptor *service_descriptor,
                                                                char *common_name,
                                                                size_t max_size)
{
    iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;

    ASSERT_OR_EXIT_MSG(service_descriptor != NULL, "Service descriptor is null");
    ASSERT_OR_EXIT_MSG(common_name != NULL, "Common name is null");

    size_t cert_len = 0;
    uint8_t cert_buffer[NXP_IOT_AGENT_CERTIFICATE_BUFFER_SIZE];

    psa_status_t psa_status = PSA_SUCCESS;
    psa_status              = psa_export_key(service_descriptor->client_certificate_sss_ref.object_id, cert_buffer,
                                             sizeof(cert_buffer), &cert_len);
    PSA_SUCCESS_OR_EXIT_MSG("Error in esporting client certificate");

    agent_status = iot_agent_get_oid_value_in_subject(cert_buffer, cert_len, "CN", common_name, max_size);
    AGENT_SUCCESS_OR_EXIT();

exit:
    return agent_status;
}

static iot_agent_status_t iot_agent_get_mqtt_service_descriptor_for_aws(nxp_iot_ServiceDescriptor *service_descriptor)
{
    iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;

    ASSERT_OR_EXIT_MSG(service_descriptor != NULL, "Service descriptor is null");

    // Service type
    service_descriptor->identifier       = AWS_SERVICE_ID;
    service_descriptor->has_service_type = true;
    service_descriptor->service_type     = nxp_iot_ServiceType_AWSSERVICE;

    // Key pair
    service_descriptor->has_client_key_sss_ref           = true;
    service_descriptor->client_key_sss_ref.has_object_id = true;
    service_descriptor->client_key_sss_ref.object_id     = AWS_SERVICE_KEY_PAIR_ID;

    // Client certificate
    service_descriptor->has_client_certificate_sss_ref           = true;
    service_descriptor->client_certificate_sss_ref.has_object_id = true;
    service_descriptor->client_certificate_sss_ref.object_id     = AWS_SERVICE_DEVICE_CERT_ID;

    // AWS MQTT connection parameters
    service_descriptor->has_port = true;
    service_descriptor->port     = 8883;

    service_descriptor->hostname = malloc(sizeof(AWS_HOSTNAME));
    ASSERT_OR_EXIT_MSG(service_descriptor->hostname != NULL, "Allocation of hostname failed");
    memcpy(service_descriptor->hostname, AWS_HOSTNAME, sizeof(AWS_HOSTNAME));

#ifdef AWS_CLIENT_ID
    service_descriptor->client_id = malloc(sizeof(AWS_CLIENT_ID));
    ASSERT_OR_EXIT_MSG(service_descriptor->client_id != NULL, "Allocation of client_id failed");
    memcpy(service_descriptor->client_id, AWS_CLIENT_ID, sizeof(AWS_CLIENT_ID));
#else
    service_descriptor->client_id = malloc(COMMON_NAME_MAX_SIZE);
    ASSERT_OR_EXIT_MSG(service_descriptor->client_id != NULL, "Allocation of client_id failed");
    memset(service_descriptor->client_id, 0, COMMON_NAME_MAX_SIZE);
    agent_status =
        iot_agent_get_certificate_common_name(service_descriptor, service_descriptor->client_id, COMMON_NAME_MAX_SIZE);
    AGENT_SUCCESS_OR_EXIT_MSG("Failed to get common name from client certificate");
#endif

exit:
    return agent_status;
}

static iot_agent_status_t iot_agent_get_service_descriptor_for_azure(nxp_iot_ServiceDescriptor *service_descriptor)
{
    iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;

    ASSERT_OR_EXIT_MSG(service_descriptor != NULL, "Service descriptor is null");

    // Service type
    service_descriptor->identifier       = AZURE_SERVICE_ID;
    service_descriptor->has_service_type = true;
    service_descriptor->service_type     = nxp_iot_ServiceType_AZURESERVICE;

    // Key pair
    service_descriptor->has_client_key_sss_ref           = true;
    service_descriptor->client_key_sss_ref.has_object_id = true;
    service_descriptor->client_key_sss_ref.object_id     = AZURE_SERVICE_KEY_PAIR_ID;

    // Client certificate
    service_descriptor->has_client_certificate_sss_ref           = true;
    service_descriptor->client_certificate_sss_ref.has_object_id = true;
    service_descriptor->client_certificate_sss_ref.object_id     = AZURE_SERVICE_DEVICE_CERT_ID;

    // Azure MQTT connection parameters
    service_descriptor->azure_id_scope = malloc(sizeof(AZURE_ID_SCOPE));
    ASSERT_OR_EXIT_MSG(service_descriptor->azure_id_scope != NULL, "Allocation of azure_id_scope failed");
    memcpy(service_descriptor->azure_id_scope, AZURE_ID_SCOPE, sizeof(AZURE_ID_SCOPE));

    service_descriptor->azure_global_device_endpoint = malloc(sizeof(AZURE_GLOBAL_DEVICE_ENDPOINT));
    ASSERT_OR_EXIT_MSG(service_descriptor->azure_global_device_endpoint != NULL,
                       "Allocation of azure_global_device_endpoint failed");
    memcpy(service_descriptor->azure_global_device_endpoint, AZURE_GLOBAL_DEVICE_ENDPOINT,
           sizeof(AZURE_GLOBAL_DEVICE_ENDPOINT));

#ifdef AZURE_REGISTRATION_ID
    service_descriptor->azure_registration_id = malloc(sizeof(AZURE_REGISTRATION_ID));
    ASSERT_OR_EXIT_MSG(service_descriptor->azure_registration_id != NULL, "Allocation of azure_registration_id failed");
    memcpy(service_descriptor->azure_registration_id, AZURE_REGISTRATION_ID, sizeof(AZURE_REGISTRATION_ID));
#else
    service_descriptor->azure_registration_id = malloc(COMMON_NAME_MAX_SIZE);
    ASSERT_OR_EXIT_MSG(service_descriptor->azure_registration_id != NULL, "Allocation of azure_registration_id failed");
    memset(service_descriptor->azure_registration_id, 0, COMMON_NAME_MAX_SIZE);
    agent_status = iot_agent_get_certificate_common_name(service_descriptor, service_descriptor->azure_registration_id,
                                                         COMMON_NAME_MAX_SIZE);
    AGENT_SUCCESS_OR_EXIT_MSG("Failed to get common name from client certificate");
#endif

exit:
    return agent_status;
}

#ifdef __ZEPHYR__
void mqtt_task(void *args, void *, void *)
#else
void mqtt_task(void *args)
#endif
{
    (void)(args);

    iot_agent_status_t agent_status                    = IOT_AGENT_SUCCESS;
    iot_agent_context_t iot_agent_context              = {0};
    nxp_iot_ServiceDescriptor aws_service_descriptor   = nxp_iot_ServiceDescriptor_init_default;
    nxp_iot_ServiceDescriptor azure_service_descriptor = nxp_iot_ServiceDescriptor_init_default;

    set_rgb_led(BLUE);

    agent_status = tfm_ns_interface_init();
    AGENT_SUCCESS_OR_EXIT_MSG("TF-M NS interface initialization failed");

    agent_status = network_init();
    AGENT_SUCCESS_OR_EXIT_MSG("Network initialization failed");

    set_rgb_led(YELLOW);

#if AWS_ENABLE
    agent_status = iot_agent_get_mqtt_service_descriptor_for_aws(&aws_service_descriptor);
    AGENT_SUCCESS_OR_EXIT();
    agent_status = iot_agent_verify_mqtt_connection_cos_over_rtp(&iot_agent_context, &aws_service_descriptor);
    AGENT_SUCCESS_OR_EXIT();
#endif

#if AZURE_ENABLE
    agent_status = iot_agent_get_service_descriptor_for_azure(&azure_service_descriptor);
    AGENT_SUCCESS_OR_EXIT();
    agent_status = iot_agent_verify_mqtt_connection_cos_over_rtp(&iot_agent_context, &azure_service_descriptor);
    AGENT_SUCCESS_OR_EXIT();
#endif

exit:
    pb_release(nxp_iot_ServiceDescriptor_fields, &aws_service_descriptor);
    pb_release(nxp_iot_ServiceDescriptor_fields, &azure_service_descriptor);

    if (agent_status == IOT_AGENT_SUCCESS)
    {
        set_rgb_led(GREEN);
        IOT_AGENT_INFO("EL2GO MQTT Client successfully finished");
    }
    else
    {
        set_rgb_led(RED);
    }

    for (;;)
        ;
}

int main(void)
{
#ifdef __ZEPHYR__
    static struct k_thread mqtt_thread_data;

    k_tid_t mqtt_thread_id =
        k_thread_create(&mqtt_thread_data, mqtt_thread_stack_area, K_THREAD_STACK_SIZEOF(mqtt_thread_stack_area),
                        mqtt_task, NULL, NULL, NULL, 0, 0, K_FOREVER);

    k_thread_name_set(mqtt_thread_id, "el2go_mqtt_task");

    k_thread_start(mqtt_thread_id);
#else
    BOARD_InitHardware();

    BaseType_t task_status =
        xTaskCreate(&mqtt_task, "el2go_mqtt_task", MQTT_THREAD_STACK_SIZE, NULL, tskIDLE_PRIORITY, NULL);
    if (task_status == pdPASS)
    {
        vTaskStartScheduler();
    }
    else
    {
        IOT_AGENT_ERROR("Failed to create MQTT task");
    }
#endif

    return 1;
}
