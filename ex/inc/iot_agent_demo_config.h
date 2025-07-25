/*
 * Copyright 2019-2025 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */
#ifndef _IOT_AGENT_DEMO_CONFIG_H_
#define _IOT_AGENT_DEMO_CONFIG_H_

#include "nxp_iot_agent_common.h"

#if defined(NXP_IOT_AGENT_HAVE_SSS) && (NXP_IOT_AGENT_HAVE_SSS == 1)
#include <sm_types.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*! @ingroup edgelock2go_agent_config
 *
 * @page page_config
 *
 * @brief
 *
 *
 * @addtogroup edgelock2go_agent_config
 * @{
 */

/**
 * SE50x based keystore
 */
#define KS_SE50X (NXP_IOT_AGENT_HAVE_SSS)

/**
 * PSA based keystore
 */
#define KS_PSA 1

/**
 * File based datastore, disabled for AX_EMBEDDED
 */
#define DS_FS (!AX_EMBEDDED)

/**
 * Use plain datastore for FreeRTOS
 */
#define DS_PLAIN (AX_EMBEDDED)

/**
 * Sanity checks for DS_*
 */
#if (DS_FS + DS_PLAIN) >= 2
#error "Multiple datastores defined"
#endif

#if (DS_FS + DS_PLAIN) == 0
#error "No datastore defined"
#endif

#ifdef __cplusplus
} // extern "C"
#endif

/**
 * Flag to enable or disable claimcode injection/encryption.
 */
#ifndef IOT_AGENT_CLAIMCODE_INJECT_ENABLE
#define IOT_AGENT_CLAIMCODE_INJECT_ENABLE 0
#endif

/**
 * This is the plain claimcode that gets encrypted and written to Flash. The
 * string used here shall match the string used on the EdgeLock 2GO cloud
 * service.
 */
#define IOT_AGENT_CLAIMCODE_STRING "insert_claimcode_from_el2go"

/**
 * Flag to enable MQTT testing
 */
#ifndef IOT_AGENT_MQTT_ENABLE
#define IOT_AGENT_MQTT_ENABLE 0
#endif

/**
 * Flag to enable nonSe provisioning
 */
#define IOT_AGENT_NONSE_TESTS_ENABLE 0

#if ((AX_EMBEDDED && defined(USE_RTOS) && USE_RTOS == 1) || \
    (defined(NXP_IOT_AGENT_HAVE_HOSTCRYPTO_OPENSSL) && (NXP_IOT_AGENT_HAVE_HOSTCRYPTO_OPENSSL == 1))) && \
    (defined(IOT_AGENT_MQTT_ENABLE) && (IOT_AGENT_MQTT_ENABLE == 1))

// doc: MQTT required modification - start

// CHANGE THIS : Set to 1 or 0 to enable or disable AWS MQTT connection
#define AWS_ENABLE 1U

// CHANGE THIS : fill with key pair and device certificate object IDs as defined on EL2GO when generating them
#ifndef AWS_SERVICE_KEY_PAIR_ID
#define AWS_SERVICE_KEY_PAIR_ID    0x83000101U
#endif

#ifndef AWS_SERVICE_DEVICE_CERT_ID
#define AWS_SERVICE_DEVICE_CERT_ID 0x83000102U
#endif

// CHANGE THIS: the AWS hostname to which the device will connect
#define AWS_HOSTNAME "aw9969rp3sm22-ats.iot.eu-central-1.amazonaws.com"

// optional: the client ID will be by default set dynamically to the Common Name of the
// device leaf certficate; is possible to hardocode it, by uncommenting the below line and assign
// the desired value
// #define AWS_CLIENT_ID "awsrtptest-0000000000001e6e-0000"

// CHANGE THIS: set the desired service ID; is used internally by the MQTT client, should be unique
// for every service
#define AWS_SERVICE_ID 101

// CHANGE THIS : Set to 1 or 0 to enable or disable Azure MQTT connection
#define AZURE_ENABLE 1U

// CHANGE THIS : fill with key pair and device certificate object IDs as defined on EL2GO when generating them
#ifndef AZURE_SERVICE_KEY_PAIR_ID
#define AZURE_SERVICE_KEY_PAIR_ID    0x83000211U
#endif

#ifndef AZURE_SERVICE_DEVICE_CERT_ID
#define AZURE_SERVICE_DEVICE_CERT_ID 0x83000212U
#endif

// CHANGE THIS : set the ID scope and the global endpoint as defined in the Azure DPS account
#define AZURE_ID_SCOPE               "0ne004510C6"
#define AZURE_GLOBAL_DEVICE_ENDPOINT "global.azure-devices-provisioning.net"

// optional: the registration ID will be by default set dynamically to the Common Name of the
// device leaf certficate; is possible to hardocode it, by uncommenting the below line and assign
// the desired value
// #define AZURE_REGISTRATION_ID "azurertptest-0000000000001e51-0000"

// CHANGE THIS: set the desired service ID; is used internally by the MQTT client, should be unique
// for every service
#define AZURE_SERVICE_ID 102

// doc: MQTT required modification - end

#define AWS_ROOT_SERVER_CERT                                                                                        \
    {                                                                                                               \
        0x30, 0x82, 0x03, 0x41, 0x30, 0x82, 0x02, 0x29, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x13, 0x06, 0x6C, 0x9F, \
            0xCF, 0x99, 0xBF, 0x8C, 0x0A, 0x39, 0xE2, 0xF0, 0x78, 0x8A, 0x43, 0xE6, 0x96, 0x36, 0x5B, 0xCA, 0x30,   \
            0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00, 0x30, 0x39, 0x31,   \
            0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x0F, 0x30, 0x0D, 0x06,   \
            0x03, 0x55, 0x04, 0x0A, 0x13, 0x06, 0x41, 0x6D, 0x61, 0x7A, 0x6F, 0x6E, 0x31, 0x19, 0x30, 0x17, 0x06,   \
            0x03, 0x55, 0x04, 0x03, 0x13, 0x10, 0x41, 0x6D, 0x61, 0x7A, 0x6F, 0x6E, 0x20, 0x52, 0x6F, 0x6F, 0x74,   \
            0x20, 0x43, 0x41, 0x20, 0x31, 0x30, 0x1E, 0x17, 0x0D, 0x31, 0x35, 0x30, 0x35, 0x32, 0x36, 0x30, 0x30,   \
            0x30, 0x30, 0x30, 0x30, 0x5A, 0x17, 0x0D, 0x33, 0x38, 0x30, 0x31, 0x31, 0x37, 0x30, 0x30, 0x30, 0x30,   \
            0x30, 0x30, 0x5A, 0x30, 0x39, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55,   \
            0x53, 0x31, 0x0F, 0x30, 0x0D, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x13, 0x06, 0x41, 0x6D, 0x61, 0x7A, 0x6F,   \
            0x6E, 0x31, 0x19, 0x30, 0x17, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x10, 0x41, 0x6D, 0x61, 0x7A, 0x6F,   \
            0x6E, 0x20, 0x52, 0x6F, 0x6F, 0x74, 0x20, 0x43, 0x41, 0x20, 0x31, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0D,   \
            0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0F,   \
            0x00, 0x30, 0x82, 0x01, 0x0A, 0x02, 0x82, 0x01, 0x01, 0x00, 0xB2, 0x78, 0x80, 0x71, 0xCA, 0x78, 0xD5,   \
            0xE3, 0x71, 0xAF, 0x47, 0x80, 0x50, 0x74, 0x7D, 0x6E, 0xD8, 0xD7, 0x88, 0x76, 0xF4, 0x99, 0x68, 0xF7,   \
            0x58, 0x21, 0x60, 0xF9, 0x74, 0x84, 0x01, 0x2F, 0xAC, 0x02, 0x2D, 0x86, 0xD3, 0xA0, 0x43, 0x7A, 0x4E,   \
            0xB2, 0xA4, 0xD0, 0x36, 0xBA, 0x01, 0xBE, 0x8D, 0xDB, 0x48, 0xC8, 0x07, 0x17, 0x36, 0x4C, 0xF4, 0xEE,   \
            0x88, 0x23, 0xC7, 0x3E, 0xEB, 0x37, 0xF5, 0xB5, 0x19, 0xF8, 0x49, 0x68, 0xB0, 0xDE, 0xD7, 0xB9, 0x76,   \
            0x38, 0x1D, 0x61, 0x9E, 0xA4, 0xFE, 0x82, 0x36, 0xA5, 0xE5, 0x4A, 0x56, 0xE4, 0x45, 0xE1, 0xF9, 0xFD,   \
            0xB4, 0x16, 0xFA, 0x74, 0xDA, 0x9C, 0x9B, 0x35, 0x39, 0x2F, 0xFA, 0xB0, 0x20, 0x50, 0x06, 0x6C, 0x7A,   \
            0xD0, 0x80, 0xB2, 0xA6, 0xF9, 0xAF, 0xEC, 0x47, 0x19, 0x8F, 0x50, 0x38, 0x07, 0xDC, 0xA2, 0x87, 0x39,   \
            0x58, 0xF8, 0xBA, 0xD5, 0xA9, 0xF9, 0x48, 0x67, 0x30, 0x96, 0xEE, 0x94, 0x78, 0x5E, 0x6F, 0x89, 0xA3,   \
            0x51, 0xC0, 0x30, 0x86, 0x66, 0xA1, 0x45, 0x66, 0xBA, 0x54, 0xEB, 0xA3, 0xC3, 0x91, 0xF9, 0x48, 0xDC,   \
            0xFF, 0xD1, 0xE8, 0x30, 0x2D, 0x7D, 0x2D, 0x74, 0x70, 0x35, 0xD7, 0x88, 0x24, 0xF7, 0x9E, 0xC4, 0x59,   \
            0x6E, 0xBB, 0x73, 0x87, 0x17, 0xF2, 0x32, 0x46, 0x28, 0xB8, 0x43, 0xFA, 0xB7, 0x1D, 0xAA, 0xCA, 0xB4,   \
            0xF2, 0x9F, 0x24, 0x0E, 0x2D, 0x4B, 0xF7, 0x71, 0x5C, 0x5E, 0x69, 0xFF, 0xEA, 0x95, 0x02, 0xCB, 0x38,   \
            0x8A, 0xAE, 0x50, 0x38, 0x6F, 0xDB, 0xFB, 0x2D, 0x62, 0x1B, 0xC5, 0xC7, 0x1E, 0x54, 0xE1, 0x77, 0xE0,   \
            0x67, 0xC8, 0x0F, 0x9C, 0x87, 0x23, 0xD6, 0x3F, 0x40, 0x20, 0x7F, 0x20, 0x80, 0xC4, 0x80, 0x4C, 0x3E,   \
            0x3B, 0x24, 0x26, 0x8E, 0x04, 0xAE, 0x6C, 0x9A, 0xC8, 0xAA, 0x0D, 0x02, 0x03, 0x01, 0x00, 0x01, 0xA3,   \
            0x42, 0x30, 0x40, 0x30, 0x0F, 0x06, 0x03, 0x55, 0x1D, 0x13, 0x01, 0x01, 0xFF, 0x04, 0x05, 0x30, 0x03,   \
            0x01, 0x01, 0xFF, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x1D, 0x0F, 0x01, 0x01, 0xFF, 0x04, 0x04, 0x03, 0x02,   \
            0x01, 0x86, 0x30, 0x1D, 0x06, 0x03, 0x55, 0x1D, 0x0E, 0x04, 0x16, 0x04, 0x14, 0x84, 0x18, 0xCC, 0x85,   \
            0x34, 0xEC, 0xBC, 0x0C, 0x94, 0x94, 0x2E, 0x08, 0x59, 0x9C, 0xC7, 0xB2, 0x10, 0x4E, 0x0A, 0x08, 0x30,   \
            0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00, 0x03, 0x82, 0x01,   \
            0x01, 0x00, 0x98, 0xF2, 0x37, 0x5A, 0x41, 0x90, 0xA1, 0x1A, 0xC5, 0x76, 0x51, 0x28, 0x20, 0x36, 0x23,   \
            0x0E, 0xAE, 0xE6, 0x28, 0xBB, 0xAA, 0xF8, 0x94, 0xAE, 0x48, 0xA4, 0x30, 0x7F, 0x1B, 0xFC, 0x24, 0x8D,   \
            0x4B, 0xB4, 0xC8, 0xA1, 0x97, 0xF6, 0xB6, 0xF1, 0x7A, 0x70, 0xC8, 0x53, 0x93, 0xCC, 0x08, 0x28, 0xE3,   \
            0x98, 0x25, 0xCF, 0x23, 0xA4, 0xF9, 0xDE, 0x21, 0xD3, 0x7C, 0x85, 0x09, 0xAD, 0x4E, 0x9A, 0x75, 0x3A,   \
            0xC2, 0x0B, 0x6A, 0x89, 0x78, 0x76, 0x44, 0x47, 0x18, 0x65, 0x6C, 0x8D, 0x41, 0x8E, 0x3B, 0x7F, 0x9A,   \
            0xCB, 0xF4, 0xB5, 0xA7, 0x50, 0xD7, 0x05, 0x2C, 0x37, 0xE8, 0x03, 0x4B, 0xAD, 0xE9, 0x61, 0xA0, 0x02,   \
            0x6E, 0xF5, 0xF2, 0xF0, 0xC5, 0xB2, 0xED, 0x5B, 0xB7, 0xDC, 0xFA, 0x94, 0x5C, 0x77, 0x9E, 0x13, 0xA5,   \
            0x7F, 0x52, 0xAD, 0x95, 0xF2, 0xF8, 0x93, 0x3B, 0xDE, 0x8B, 0x5C, 0x5B, 0xCA, 0x5A, 0x52, 0x5B, 0x60,   \
            0xAF, 0x14, 0xF7, 0x4B, 0xEF, 0xA3, 0xFB, 0x9F, 0x40, 0x95, 0x6D, 0x31, 0x54, 0xFC, 0x42, 0xD3, 0xC7,   \
            0x46, 0x1F, 0x23, 0xAD, 0xD9, 0x0F, 0x48, 0x70, 0x9A, 0xD9, 0x75, 0x78, 0x71, 0xD1, 0x72, 0x43, 0x34,   \
            0x75, 0x6E, 0x57, 0x59, 0xC2, 0x02, 0x5C, 0x26, 0x60, 0x29, 0xCF, 0x23, 0x19, 0x16, 0x8E, 0x88, 0x43,   \
            0xA5, 0xD4, 0xE4, 0xCB, 0x08, 0xFB, 0x23, 0x11, 0x43, 0xE8, 0x43, 0x29, 0x72, 0x62, 0xA1, 0xA9, 0x5D,   \
            0x5E, 0x08, 0xD4, 0x90, 0xAE, 0xB8, 0xD8, 0xCE, 0x14, 0xC2, 0xD0, 0x55, 0xF2, 0x86, 0xF6, 0xC4, 0x93,   \
            0x43, 0x77, 0x66, 0x61, 0xC0, 0xB9, 0xE8, 0x41, 0xD7, 0x97, 0x78, 0x60, 0x03, 0x6E, 0x4A, 0x72, 0xAE,   \
            0xA5, 0xD1, 0x7D, 0xBA, 0x10, 0x9E, 0x86, 0x6C, 0x1B, 0x8A, 0xB9, 0x59, 0x33, 0xF8, 0xEB, 0xC4, 0x90,   \
            0xBE, 0xF1, 0xB9                                                                                        \
    }
#define AWS_ROOT_SERVER_CERT_SIZE 837

#define AZURE_ROOT_SERVER_CERT                                                                                      \
    {                                                                                                               \
        0x30, 0x82, 0x03, 0x8e, 0x30, 0x82, 0x02, 0x76, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x10, 0x03, 0x3a, 0xf1, \
            0xe6, 0xa7, 0x11, 0xa9, 0xa0, 0xbb, 0x28, 0x64, 0xb1, 0x1d, 0x09, 0xfa, 0xe5, 0x30, 0x0d, 0x06, 0x09,   \
            0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x30, 0x61, 0x31, 0x0b, 0x30, 0x09,   \
            0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04,   \
            0x0a, 0x13, 0x0c, 0x44, 0x69, 0x67, 0x69, 0x43, 0x65, 0x72, 0x74, 0x20, 0x49, 0x6e, 0x63, 0x31, 0x19,   \
            0x30, 0x17, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x13, 0x10, 0x77, 0x77, 0x77, 0x2e, 0x64, 0x69, 0x67, 0x69,   \
            0x63, 0x65, 0x72, 0x74, 0x2e, 0x63, 0x6f, 0x6d, 0x31, 0x20, 0x30, 0x1e, 0x06, 0x03, 0x55, 0x04, 0x03,   \
            0x13, 0x17, 0x44, 0x69, 0x67, 0x69, 0x43, 0x65, 0x72, 0x74, 0x20, 0x47, 0x6c, 0x6f, 0x62, 0x61, 0x6c,   \
            0x20, 0x52, 0x6f, 0x6f, 0x74, 0x20, 0x47, 0x32, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x33, 0x30, 0x38, 0x30,   \
            0x31, 0x31, 0x32, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x17, 0x0d, 0x33, 0x38, 0x30, 0x31, 0x31, 0x35, 0x31,   \
            0x32, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x30, 0x61, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06,   \
            0x13, 0x02, 0x55, 0x53, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x0c, 0x44, 0x69,   \
            0x67, 0x69, 0x43, 0x65, 0x72, 0x74, 0x20, 0x49, 0x6e, 0x63, 0x31, 0x19, 0x30, 0x17, 0x06, 0x03, 0x55,   \
            0x04, 0x0b, 0x13, 0x10, 0x77, 0x77, 0x77, 0x2e, 0x64, 0x69, 0x67, 0x69, 0x63, 0x65, 0x72, 0x74, 0x2e,   \
            0x63, 0x6f, 0x6d, 0x31, 0x20, 0x30, 0x1e, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x17, 0x44, 0x69, 0x67,   \
            0x69, 0x43, 0x65, 0x72, 0x74, 0x20, 0x47, 0x6c, 0x6f, 0x62, 0x61, 0x6c, 0x20, 0x52, 0x6f, 0x6f, 0x74,   \
            0x20, 0x47, 0x32, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,   \
            0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01,   \
            0x01, 0x00, 0xbb, 0x37, 0xcd, 0x34, 0xdc, 0x7b, 0x6b, 0xc9, 0xb2, 0x68, 0x90, 0xad, 0x4a, 0x75, 0xff,   \
            0x46, 0xba, 0x21, 0x0a, 0x08, 0x8d, 0xf5, 0x19, 0x54, 0xc9, 0xfb, 0x88, 0xdb, 0xf3, 0xae, 0xf2, 0x3a,   \
            0x89, 0x91, 0x3c, 0x7a, 0xe6, 0xab, 0x06, 0x1a, 0x6b, 0xcf, 0xac, 0x2d, 0xe8, 0x5e, 0x09, 0x24, 0x44,   \
            0xba, 0x62, 0x9a, 0x7e, 0xd6, 0xa3, 0xa8, 0x7e, 0xe0, 0x54, 0x75, 0x20, 0x05, 0xac, 0x50, 0xb7, 0x9c,   \
            0x63, 0x1a, 0x6c, 0x30, 0xdc, 0xda, 0x1f, 0x19, 0xb1, 0xd7, 0x1e, 0xde, 0xfd, 0xd7, 0xe0, 0xcb, 0x94,   \
            0x83, 0x37, 0xae, 0xec, 0x1f, 0x43, 0x4e, 0xdd, 0x7b, 0x2c, 0xd2, 0xbd, 0x2e, 0xa5, 0x2f, 0xe4, 0xa9,   \
            0xb8, 0xad, 0x3a, 0xd4, 0x99, 0xa4, 0xb6, 0x25, 0xe9, 0x9b, 0x6b, 0x00, 0x60, 0x92, 0x60, 0xff, 0x4f,   \
            0x21, 0x49, 0x18, 0xf7, 0x67, 0x90, 0xab, 0x61, 0x06, 0x9c, 0x8f, 0xf2, 0xba, 0xe9, 0xb4, 0xe9, 0x92,   \
            0x32, 0x6b, 0xb5, 0xf3, 0x57, 0xe8, 0x5d, 0x1b, 0xcd, 0x8c, 0x1d, 0xab, 0x95, 0x04, 0x95, 0x49, 0xf3,   \
            0x35, 0x2d, 0x96, 0xe3, 0x49, 0x6d, 0xdd, 0x77, 0xe3, 0xfb, 0x49, 0x4b, 0xb4, 0xac, 0x55, 0x07, 0xa9,   \
            0x8f, 0x95, 0xb3, 0xb4, 0x23, 0xbb, 0x4c, 0x6d, 0x45, 0xf0, 0xf6, 0xa9, 0xb2, 0x95, 0x30, 0xb4, 0xfd,   \
            0x4c, 0x55, 0x8c, 0x27, 0x4a, 0x57, 0x14, 0x7c, 0x82, 0x9d, 0xcd, 0x73, 0x92, 0xd3, 0x16, 0x4a, 0x06,   \
            0x0c, 0x8c, 0x50, 0xd1, 0x8f, 0x1e, 0x09, 0xbe, 0x17, 0xa1, 0xe6, 0x21, 0xca, 0xfd, 0x83, 0xe5, 0x10,   \
            0xbc, 0x83, 0xa5, 0x0a, 0xc4, 0x67, 0x28, 0xf6, 0x73, 0x14, 0x14, 0x3d, 0x46, 0x76, 0xc3, 0x87, 0x14,   \
            0x89, 0x21, 0x34, 0x4d, 0xaf, 0x0f, 0x45, 0x0c, 0xa6, 0x49, 0xa1, 0xba, 0xbb, 0x9c, 0xc5, 0xb1, 0x33,   \
            0x83, 0x29, 0x85, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x42, 0x30, 0x40, 0x30, 0x0f, 0x06, 0x03, 0x55,   \
            0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x0e, 0x06, 0x03, 0x55,   \
            0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x01, 0x86, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d,   \
            0x0e, 0x04, 0x16, 0x04, 0x14, 0x4e, 0x22, 0x54, 0x20, 0x18, 0x95, 0xe6, 0xe3, 0x6e, 0xe6, 0x0f, 0xfa,   \
            0xfa, 0xb9, 0x12, 0xed, 0x06, 0x17, 0x8f, 0x39, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,   \
            0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0x60, 0x67, 0x28, 0x94, 0x6f, 0x0e,   \
            0x48, 0x63, 0xeb, 0x31, 0xdd, 0xea, 0x67, 0x18, 0xd5, 0x89, 0x7d, 0x3c, 0xc5, 0x8b, 0x4a, 0x7f, 0xe9,   \
            0xbe, 0xdb, 0x2b, 0x17, 0xdf, 0xb0, 0x5f, 0x73, 0x77, 0x2a, 0x32, 0x13, 0x39, 0x81, 0x67, 0x42, 0x84,   \
            0x23, 0xf2, 0x45, 0x67, 0x35, 0xec, 0x88, 0xbf, 0xf8, 0x8f, 0xb0, 0x61, 0x0c, 0x34, 0xa4, 0xae, 0x20,   \
            0x4c, 0x84, 0xc6, 0xdb, 0xf8, 0x35, 0xe1, 0x76, 0xd9, 0xdf, 0xa6, 0x42, 0xbb, 0xc7, 0x44, 0x08, 0x86,   \
            0x7f, 0x36, 0x74, 0x24, 0x5a, 0xda, 0x6c, 0x0d, 0x14, 0x59, 0x35, 0xbd, 0xf2, 0x49, 0xdd, 0xb6, 0x1f,   \
            0xc9, 0xb3, 0x0d, 0x47, 0x2a, 0x3d, 0x99, 0x2f, 0xbb, 0x5c, 0xbb, 0xb5, 0xd4, 0x20, 0xe1, 0x99, 0x5f,   \
            0x53, 0x46, 0x15, 0xdb, 0x68, 0x9b, 0xf0, 0xf3, 0x30, 0xd5, 0x3e, 0x31, 0xe2, 0x8d, 0x84, 0x9e, 0xe3,   \
            0x8a, 0xda, 0xda, 0x96, 0x3e, 0x35, 0x13, 0xa5, 0x5f, 0xf0, 0xf9, 0x70, 0x50, 0x70, 0x47, 0x41, 0x11,   \
            0x57, 0x19, 0x4e, 0xc0, 0x8f, 0xae, 0x06, 0xc4, 0x95, 0x13, 0x17, 0x2f, 0x1b, 0x25, 0x9f, 0x75, 0xf2,   \
            0xb1, 0x8e, 0x99, 0xa1, 0x6f, 0x13, 0xb1, 0x41, 0x71, 0xfe, 0x88, 0x2a, 0xc8, 0x4f, 0x10, 0x20, 0x55,   \
            0xd7, 0xf3, 0x14, 0x45, 0xe5, 0xe0, 0x44, 0xf4, 0xea, 0x87, 0x95, 0x32, 0x93, 0x0e, 0xfe, 0x53, 0x46,   \
            0xfa, 0x2c, 0x9d, 0xff, 0x8b, 0x22, 0xb9, 0x4b, 0xd9, 0x09, 0x45, 0xa4, 0xde, 0xa4, 0xb8, 0x9a, 0x58,   \
            0xdd, 0x1b, 0x7d, 0x52, 0x9f, 0x8e, 0x59, 0x43, 0x88, 0x81, 0xa4, 0x9e, 0x26, 0xd5, 0x6f, 0xad, 0xdd,   \
            0x0d, 0xc6, 0x37, 0x7d, 0xed, 0x03, 0x92, 0x1b, 0xe5, 0x77, 0x5f, 0x76, 0xee, 0x3c, 0x8d, 0xc4, 0x5d,   \
            0x56, 0x5b, 0xa2, 0xd9, 0x66, 0x6e, 0xb3, 0x35, 0x37, 0xe5, 0x32, 0xb6                                  \
    }
#define AZURE_ROOT_SERVER_CERT_SIZE 920

#endif
/*!
 *@}
 */ /* end of edgelock2go_agent_config */

#endif // #ifndef _IOT_AGENT_DEMO_CONFIG_H_
