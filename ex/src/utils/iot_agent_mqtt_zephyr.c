/* 
 * Copyright 2024-2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 * 
 */

#include <iot_agent_mqtt_zephyr.h>
#include <nxp_iot_agent_macros.h>
#include <nxp_iot_agent_macros_psa.h>

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

// AZURE CONFIG

#define AZURE_MQTT_REGISTER_HOSTNAME      "global.azure-devices-provisioning.net"
#define AZURE_MQTT_REGISTER_PORT          8883U
#define AZURE_MQTT_REGISTRATION_MSG_TOPIC "$dps/registrations/PUT/iotdps-register/?$rid=1"
#define AZURE_MQTT_PUBLISH_MSG_OPID_AZURE "$dps/registrations/GET/iotdps-get-operationstatus/?$rid=2&operationId="
#define AZURE_MQTT_SUBSCRIBE_MSG_TOPIC    "$dps/registrations/res/#"

#define AZURE_MQTT_REGISTRATION_WAIT_COUNT 20U

#if defined(MBEDTLS_VERSION_NUMBER) && (MBEDTLS_VERSION_NUMBER >= 0x04000000)
static const char AWS_SERVER_ROOT_CERTIFICATE[] = {
    // in case of MbedTLS 4.x the PEM parsing is not allowed in NS word and since ATM there is no PEM to DER
    // parsing API exposed by TF-M, we change the root CAs to be in DER format
    0x30, 0x82, 0x03, 0x41, 0x30, 0x82, 0x02, 0x29, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x13, 0x06,
    0x6C, 0x9F, 0xCF, 0x99, 0xBF, 0x8C, 0x0A, 0x39, 0xE2, 0xF0, 0x78, 0x8A, 0x43, 0xE6, 0x96, 0x36,
    0x5B, 0xCA, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05,
    0x00, 0x30, 0x39, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53,
    0x31, 0x0F, 0x30, 0x0D, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x13, 0x06, 0x41, 0x6D, 0x61, 0x7A, 0x6F,
    0x6E, 0x31, 0x19, 0x30, 0x17, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x10, 0x41, 0x6D, 0x61, 0x7A,
    0x6F, 0x6E, 0x20, 0x52, 0x6F, 0x6F, 0x74, 0x20, 0x43, 0x41, 0x20, 0x31, 0x30, 0x1E, 0x17, 0x0D,
    0x31, 0x35, 0x30, 0x35, 0x32, 0x36, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5A, 0x17, 0x0D, 0x33,
    0x38, 0x30, 0x31, 0x31, 0x37, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5A, 0x30, 0x39, 0x31, 0x0B,
    0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x0F, 0x30, 0x0D, 0x06,
    0x03, 0x55, 0x04, 0x0A, 0x13, 0x06, 0x41, 0x6D, 0x61, 0x7A, 0x6F, 0x6E, 0x31, 0x19, 0x30, 0x17,
    0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x10, 0x41, 0x6D, 0x61, 0x7A, 0x6F, 0x6E, 0x20, 0x52, 0x6F,
    0x6F, 0x74, 0x20, 0x43, 0x41, 0x20, 0x31, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0D, 0x06, 0x09, 0x2A,
    0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0F, 0x00, 0x30,
    0x82, 0x01, 0x0A, 0x02, 0x82, 0x01, 0x01, 0x00, 0xB2, 0x78, 0x80, 0x71, 0xCA, 0x78, 0xD5, 0xE3,
    0x71, 0xAF, 0x47, 0x80, 0x50, 0x74, 0x7D, 0x6E, 0xD8, 0xD7, 0x88, 0x76, 0xF4, 0x99, 0x68, 0xF7,
    0x58, 0x21, 0x60, 0xF9, 0x74, 0x84, 0x01, 0x2F, 0xAC, 0x02, 0x2D, 0x86, 0xD3, 0xA0, 0x43, 0x7A,
    0x4E, 0xB2, 0xA4, 0xD0, 0x36, 0xBA, 0x01, 0xBE, 0x8D, 0xDB, 0x48, 0xC8, 0x07, 0x17, 0x36, 0x4C,
    0xF4, 0xEE, 0x88, 0x23, 0xC7, 0x3E, 0xEB, 0x37, 0xF5, 0xB5, 0x19, 0xF8, 0x49, 0x68, 0xB0, 0xDE,
    0xD7, 0xB9, 0x76, 0x38, 0x1D, 0x61, 0x9E, 0xA4, 0xFE, 0x82, 0x36, 0xA5, 0xE5, 0x4A, 0x56, 0xE4,
    0x45, 0xE1, 0xF9, 0xFD, 0xB4, 0x16, 0xFA, 0x74, 0xDA, 0x9C, 0x9B, 0x35, 0x39, 0x2F, 0xFA, 0xB0,
    0x20, 0x50, 0x06, 0x6C, 0x7A, 0xD0, 0x80, 0xB2, 0xA6, 0xF9, 0xAF, 0xEC, 0x47, 0x19, 0x8F, 0x50,
    0x38, 0x07, 0xDC, 0xA2, 0x87, 0x39, 0x58, 0xF8, 0xBA, 0xD5, 0xA9, 0xF9, 0x48, 0x67, 0x30, 0x96,
    0xEE, 0x94, 0x78, 0x5E, 0x6F, 0x89, 0xA3, 0x51, 0xC0, 0x30, 0x86, 0x66, 0xA1, 0x45, 0x66, 0xBA,
    0x54, 0xEB, 0xA3, 0xC3, 0x91, 0xF9, 0x48, 0xDC, 0xFF, 0xD1, 0xE8, 0x30, 0x2D, 0x7D, 0x2D, 0x74,
    0x70, 0x35, 0xD7, 0x88, 0x24, 0xF7, 0x9E, 0xC4, 0x59, 0x6E, 0xBB, 0x73, 0x87, 0x17, 0xF2, 0x32,
    0x46, 0x28, 0xB8, 0x43, 0xFA, 0xB7, 0x1D, 0xAA, 0xCA, 0xB4, 0xF2, 0x9F, 0x24, 0x0E, 0x2D, 0x4B,
    0xF7, 0x71, 0x5C, 0x5E, 0x69, 0xFF, 0xEA, 0x95, 0x02, 0xCB, 0x38, 0x8A, 0xAE, 0x50, 0x38, 0x6F,
    0xDB, 0xFB, 0x2D, 0x62, 0x1B, 0xC5, 0xC7, 0x1E, 0x54, 0xE1, 0x77, 0xE0, 0x67, 0xC8, 0x0F, 0x9C,
    0x87, 0x23, 0xD6, 0x3F, 0x40, 0x20, 0x7F, 0x20, 0x80, 0xC4, 0x80, 0x4C, 0x3E, 0x3B, 0x24, 0x26,
    0x8E, 0x04, 0xAE, 0x6C, 0x9A, 0xC8, 0xAA, 0x0D, 0x02, 0x03, 0x01, 0x00, 0x01, 0xA3, 0x42, 0x30,
    0x40, 0x30, 0x0F, 0x06, 0x03, 0x55, 0x1D, 0x13, 0x01, 0x01, 0xFF, 0x04, 0x05, 0x30, 0x03, 0x01,
    0x01, 0xFF, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x1D, 0x0F, 0x01, 0x01, 0xFF, 0x04, 0x04, 0x03, 0x02,
    0x01, 0x86, 0x30, 0x1D, 0x06, 0x03, 0x55, 0x1D, 0x0E, 0x04, 0x16, 0x04, 0x14, 0x84, 0x18, 0xCC,
    0x85, 0x34, 0xEC, 0xBC, 0x0C, 0x94, 0x94, 0x2E, 0x08, 0x59, 0x9C, 0xC7, 0xB2, 0x10, 0x4E, 0x0A,
    0x08, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00,
    0x03, 0x82, 0x01, 0x01, 0x00, 0x98, 0xF2, 0x37, 0x5A, 0x41, 0x90, 0xA1, 0x1A, 0xC5, 0x76, 0x51,
    0x28, 0x20, 0x36, 0x23, 0x0E, 0xAE, 0xE6, 0x28, 0xBB, 0xAA, 0xF8, 0x94, 0xAE, 0x48, 0xA4, 0x30,
    0x7F, 0x1B, 0xFC, 0x24, 0x8D, 0x4B, 0xB4, 0xC8, 0xA1, 0x97, 0xF6, 0xB6, 0xF1, 0x7A, 0x70, 0xC8,
    0x53, 0x93, 0xCC, 0x08, 0x28, 0xE3, 0x98, 0x25, 0xCF, 0x23, 0xA4, 0xF9, 0xDE, 0x21, 0xD3, 0x7C,
    0x85, 0x09, 0xAD, 0x4E, 0x9A, 0x75, 0x3A, 0xC2, 0x0B, 0x6A, 0x89, 0x78, 0x76, 0x44, 0x47, 0x18,
    0x65, 0x6C, 0x8D, 0x41, 0x8E, 0x3B, 0x7F, 0x9A, 0xCB, 0xF4, 0xB5, 0xA7, 0x50, 0xD7, 0x05, 0x2C,
    0x37, 0xE8, 0x03, 0x4B, 0xAD, 0xE9, 0x61, 0xA0, 0x02, 0x6E, 0xF5, 0xF2, 0xF0, 0xC5, 0xB2, 0xED,
    0x5B, 0xB7, 0xDC, 0xFA, 0x94, 0x5C, 0x77, 0x9E, 0x13, 0xA5, 0x7F, 0x52, 0xAD, 0x95, 0xF2, 0xF8,
    0x93, 0x3B, 0xDE, 0x8B, 0x5C, 0x5B, 0xCA, 0x5A, 0x52, 0x5B, 0x60, 0xAF, 0x14, 0xF7, 0x4B, 0xEF,
    0xA3, 0xFB, 0x9F, 0x40, 0x95, 0x6D, 0x31, 0x54, 0xFC, 0x42, 0xD3, 0xC7, 0x46, 0x1F, 0x23, 0xAD,
    0xD9, 0x0F, 0x48, 0x70, 0x9A, 0xD9, 0x75, 0x78, 0x71, 0xD1, 0x72, 0x43, 0x34, 0x75, 0x6E, 0x57,
    0x59, 0xC2, 0x02, 0x5C, 0x26, 0x60, 0x29, 0xCF, 0x23, 0x19, 0x16, 0x8E, 0x88, 0x43, 0xA5, 0xD4,
    0xE4, 0xCB, 0x08, 0xFB, 0x23, 0x11, 0x43, 0xE8, 0x43, 0x29, 0x72, 0x62, 0xA1, 0xA9, 0x5D, 0x5E,
    0x08, 0xD4, 0x90, 0xAE, 0xB8, 0xD8, 0xCE, 0x14, 0xC2, 0xD0, 0x55, 0xF2, 0x86, 0xF6, 0xC4, 0x93,
    0x43, 0x77, 0x66, 0x61, 0xC0, 0xB9, 0xE8, 0x41, 0xD7, 0x97, 0x78, 0x60, 0x03, 0x6E, 0x4A, 0x72,
    0xAE, 0xA5, 0xD1, 0x7D, 0xBA, 0x10, 0x9E, 0x86, 0x6C, 0x1B, 0x8A, 0xB9, 0x59, 0x33, 0xF8, 0xEB,
    0xC4, 0x90, 0xBE, 0xF1, 0xB9};

static const char AZURE_SERVER_ROOT_CERTIFICATE[] = {
    0x30, 0x82, 0x03, 0x8E, 0x30, 0x82, 0x02, 0x76, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x10, 0x03,
    0x3A, 0xF1, 0xE6, 0xA7, 0x11, 0xA9, 0xA0, 0xBB, 0x28, 0x64, 0xB1, 0x1D, 0x09, 0xFA, 0xE5, 0x30,
    0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00, 0x30, 0x61,
    0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x15, 0x30,
    0x13, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x13, 0x0C, 0x44, 0x69, 0x67, 0x69, 0x43, 0x65, 0x72, 0x74,
    0x20, 0x49, 0x6E, 0x63, 0x31, 0x19, 0x30, 0x17, 0x06, 0x03, 0x55, 0x04, 0x0B, 0x13, 0x10, 0x77,
    0x77, 0x77, 0x2E, 0x64, 0x69, 0x67, 0x69, 0x63, 0x65, 0x72, 0x74, 0x2E, 0x63, 0x6F, 0x6D, 0x31,
    0x20, 0x30, 0x1E, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x17, 0x44, 0x69, 0x67, 0x69, 0x43, 0x65,
    0x72, 0x74, 0x20, 0x47, 0x6C, 0x6F, 0x62, 0x61, 0x6C, 0x20, 0x52, 0x6F, 0x6F, 0x74, 0x20, 0x47,
    0x32, 0x30, 0x1E, 0x17, 0x0D, 0x31, 0x33, 0x30, 0x38, 0x30, 0x31, 0x31, 0x32, 0x30, 0x30, 0x30,
    0x30, 0x5A, 0x17, 0x0D, 0x33, 0x38, 0x30, 0x31, 0x31, 0x35, 0x31, 0x32, 0x30, 0x30, 0x30, 0x30,
    0x5A, 0x30, 0x61, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53,
    0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x13, 0x0C, 0x44, 0x69, 0x67, 0x69, 0x43,
    0x65, 0x72, 0x74, 0x20, 0x49, 0x6E, 0x63, 0x31, 0x19, 0x30, 0x17, 0x06, 0x03, 0x55, 0x04, 0x0B,
    0x13, 0x10, 0x77, 0x77, 0x77, 0x2E, 0x64, 0x69, 0x67, 0x69, 0x63, 0x65, 0x72, 0x74, 0x2E, 0x63,
    0x6F, 0x6D, 0x31, 0x20, 0x30, 0x1E, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x17, 0x44, 0x69, 0x67,
    0x69, 0x43, 0x65, 0x72, 0x74, 0x20, 0x47, 0x6C, 0x6F, 0x62, 0x61, 0x6C, 0x20, 0x52, 0x6F, 0x6F,
    0x74, 0x20, 0x47, 0x32, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86,
    0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0F, 0x00, 0x30, 0x82, 0x01, 0x0A,
    0x02, 0x82, 0x01, 0x01, 0x00, 0xBB, 0x37, 0xCD, 0x34, 0xDC, 0x7B, 0x6B, 0xC9, 0xB2, 0x68, 0x90,
    0xAD, 0x4A, 0x75, 0xFF, 0x46, 0xBA, 0x21, 0x0A, 0x08, 0x8D, 0xF5, 0x19, 0x54, 0xC9, 0xFB, 0x88,
    0xDB, 0xF3, 0xAE, 0xF2, 0x3A, 0x89, 0x91, 0x3C, 0x7A, 0xE6, 0xAB, 0x06, 0x1A, 0x6B, 0xCF, 0xAC,
    0x2D, 0xE8, 0x5E, 0x09, 0x24, 0x44, 0xBA, 0x62, 0x9A, 0x7E, 0xD6, 0xA3, 0xA8, 0x7E, 0xE0, 0x54,
    0x75, 0x20, 0x05, 0xAC, 0x50, 0xB7, 0x9C, 0x63, 0x1A, 0x6C, 0x30, 0xDC, 0xDA, 0x1F, 0x19, 0xB1,
    0xD7, 0x1E, 0xDE, 0xFD, 0xD7, 0xE0, 0xCB, 0x94, 0x83, 0x37, 0xAE, 0xEC, 0x1F, 0x43, 0x4E, 0xDD,
    0x7B, 0x2C, 0xD2, 0xBD, 0x2E, 0xA5, 0x2F, 0xE4, 0xA9, 0xB8, 0xAD, 0x3A, 0xD4, 0x99, 0xA4, 0xB6,
    0x25, 0xE9, 0x9B, 0x6B, 0x00, 0x60, 0x92, 0x60, 0xFF, 0x4F, 0x21, 0x49, 0x18, 0xF7, 0x67, 0x90,
    0xAB, 0x61, 0x06, 0x9C, 0x8F, 0xF2, 0xBA, 0xE9, 0xB4, 0xE9, 0x92, 0x32, 0x6B, 0xB5, 0xF3, 0x57,
    0xE8, 0x5D, 0x1B, 0xCD, 0x8C, 0x1D, 0xAB, 0x95, 0x04, 0x95, 0x49, 0xF3, 0x35, 0x2D, 0x96, 0xE3,
    0x49, 0x6D, 0xDD, 0x77, 0xE3, 0xFB, 0x49, 0x4B, 0xB4, 0xAC, 0x55, 0x07, 0xA9, 0x8F, 0x95, 0xB3,
    0xB4, 0x23, 0xBB, 0x4C, 0x6D, 0x45, 0xF0, 0xF6, 0xA9, 0xB2, 0x95, 0x30, 0xB4, 0xFD, 0x4C, 0x55,
    0x8C, 0x27, 0x4A, 0x57, 0x14, 0x7C, 0x82, 0x9D, 0xCD, 0x73, 0x92, 0xD3, 0x16, 0x4A, 0x06, 0x0C,
    0x8C, 0x50, 0xD1, 0x8F, 0x1E, 0x09, 0xBE, 0x17, 0xA1, 0xE6, 0x21, 0xCA, 0xFD, 0x83, 0xE5, 0x10,
    0xBC, 0x83, 0xA5, 0x0A, 0xC4, 0x67, 0x28, 0xF6, 0x73, 0x14, 0x14, 0x3D, 0x46, 0x76, 0xC3, 0x87,
    0x14, 0x89, 0x21, 0x34, 0x4D, 0xAF, 0x0F, 0x45, 0x0C, 0xA6, 0x49, 0xA1, 0xBA, 0xBB, 0x9C, 0xC5,
    0xB1, 0x33, 0x83, 0x29, 0x85, 0x02, 0x03, 0x01, 0x00, 0x01, 0xA3, 0x42, 0x30, 0x40, 0x30, 0x0F,
    0x06, 0x03, 0x55, 0x1D, 0x13, 0x01, 0x01, 0xFF, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xFF, 0x30,
    0x0E, 0x06, 0x03, 0x55, 0x1D, 0x0F, 0x01, 0x01, 0xFF, 0x04, 0x04, 0x03, 0x02, 0x01, 0x86, 0x30,
    0x1D, 0x06, 0x03, 0x55, 0x1D, 0x0E, 0x04, 0x16, 0x04, 0x14, 0x4E, 0x22, 0x54, 0x20, 0x18, 0x95,
    0xE6, 0xE3, 0x6E, 0xE6, 0x0F, 0xFA, 0xFA, 0xB9, 0x12, 0xED, 0x06, 0x17, 0x8F, 0x39, 0x30, 0x0D,
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00, 0x03, 0x82, 0x01,
    0x01, 0x00, 0x60, 0x67, 0x28, 0x94, 0x6F, 0x0E, 0x48, 0x63, 0xEB, 0x31, 0xDD, 0xEA, 0x67, 0x18,
    0xD5, 0x89, 0x7D, 0x3C, 0xC5, 0x8B, 0x4A, 0x7F, 0xE9, 0xBE, 0xDB, 0x2B, 0x17, 0xDF, 0xB0, 0x5F,
    0x73, 0x77, 0x2A, 0x32, 0x13, 0x39, 0x81, 0x67, 0x42, 0x84, 0x23, 0xF2, 0x45, 0x67, 0x35, 0xEC,
    0x88, 0xBF, 0xF8, 0x8F, 0xB0, 0x61, 0x0C, 0x34, 0xA4, 0xAE, 0x20, 0x4C, 0x84, 0xC6, 0xDB, 0xF8,
    0x35, 0xE1, 0x76, 0xD9, 0xDF, 0xA6, 0x42, 0xBB, 0xC7, 0x44, 0x08, 0x86, 0x7F, 0x36, 0x74, 0x24,
    0x5A, 0xDA, 0x6C, 0x0D, 0x14, 0x59, 0x35, 0xBD, 0xF2, 0x49, 0xDD, 0xB6, 0x1F, 0xC9, 0xB3, 0x0D,
    0x47, 0x2A, 0x3D, 0x99, 0x2F, 0xBB, 0x5C, 0xBB, 0xB5, 0xD4, 0x20, 0xE1, 0x99, 0x5F, 0x53, 0x46,
    0x15, 0xDB, 0x68, 0x9B, 0xF0, 0xF3, 0x30, 0xD5, 0x3E, 0x31, 0xE2, 0x8D, 0x84, 0x9E, 0xE3, 0x8A,
    0xDA, 0xDA, 0x96, 0x3E, 0x35, 0x13, 0xA5, 0x5F, 0xF0, 0xF9, 0x70, 0x50, 0x70, 0x47, 0x41, 0x11,
    0x57, 0x19, 0x4E, 0xC0, 0x8F, 0xAE, 0x06, 0xC4, 0x95, 0x13, 0x17, 0x2F, 0x1B, 0x25, 0x9F, 0x75,
    0xF2, 0xB1, 0x8E, 0x99, 0xA1, 0x6F, 0x13, 0xB1, 0x41, 0x71, 0xFE, 0x88, 0x2A, 0xC8, 0x4F, 0x10,
    0x20, 0x55, 0xD7, 0xF3, 0x14, 0x45, 0xE5, 0xE0, 0x44, 0xF4, 0xEA, 0x87, 0x95, 0x32, 0x93, 0x0E,
    0xFE, 0x53, 0x46, 0xFA, 0x2C, 0x9D, 0xFF, 0x8B, 0x22, 0xB9, 0x4B, 0xD9, 0x09, 0x45, 0xA4, 0xDE,
    0xA4, 0xB8, 0x9A, 0x58, 0xDD, 0x1B, 0x7D, 0x52, 0x9F, 0x8E, 0x59, 0x43, 0x88, 0x81, 0xA4, 0x9E,
    0x26, 0xD5, 0x6F, 0xAD, 0xDD, 0x0D, 0xC6, 0x37, 0x7D, 0xED, 0x03, 0x92, 0x1B, 0xE5, 0x77, 0x5F,
    0x76, 0xEE, 0x3C, 0x8D, 0xC4, 0x5D, 0x56, 0x5B, 0xA2, 0xD9, 0x66, 0x6E, 0xB3, 0x35, 0x37, 0xE5,
    0x32, 0xB6};
#else

static const char AWS_SERVER_ROOT_CERTIFICATE[] =
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

static const char AZURE_SERVER_ROOT_CERTIFICATE[] =
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

#endif //#if defined(MBEDTLS_VERSION_NUMBER) && (MBEDTLS_VERSION_NUMBER >= 0x04000000)

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
    psa_status = network_pk_wrap_psa_key(&network_ctx->pkey, key_id);
    PSA_SUCCESS_OR_EXIT_MSG("Could not setup mbedtls opaque client key");

exit:
    free(client_cert);
	free(network_config);

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
        else
        {
            IOT_AGENT_ERROR("No CONNACK event received");
            mqtt_disconnect(client, NULL);
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
        AWS_SERVER_ROOT_CERTIFICATE, sizeof(AWS_SERVER_ROOT_CERTIFICATE)
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
    mqtt_disconnect(&client_ctx, NULL);
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
        AZURE_SERVER_ROOT_CERTIFICATE, sizeof(AZURE_SERVER_ROOT_CERTIFICATE)
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
    mqtt_disconnect(&client_ctx, NULL);
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
        AZURE_SERVER_ROOT_CERTIFICATE, sizeof(AZURE_SERVER_ROOT_CERTIFICATE)
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
    mqtt_disconnect(&client_ctx, NULL);
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
