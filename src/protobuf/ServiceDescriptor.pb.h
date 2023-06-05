/* Copyright 2022 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */
/* Automatically generated nanopb header */
/* Generated by nanopb-0.3.9.4 at Fri Mar 11 11:00:03 2022. */

#ifndef PB_NXP_IOT_SERVICEDESCRIPTOR_PB_H_INCLUDED
#define PB_NXP_IOT_SERVICEDESCRIPTOR_PB_H_INCLUDED
#include <pb.h>

#include "Types.pb.h"

/* @@protoc_insertion_point(includes) */
#if PB_PROTO_HEADER_VERSION != 30
#error Regenerate this file with the current version of nanopb generator.
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Struct definitions */
typedef struct _nxp_iot_SssObjectReference {
    bool has_type;
    nxp_iot_EndpointType type;
    bool has_endpoint_id;
    uint32_t endpoint_id;
    bool has_object_id;
    uint32_t object_id;
/* @@protoc_insertion_point(struct:nxp_iot_SssObjectReference) */
} nxp_iot_SssObjectReference;

typedef struct _nxp_iot_ServiceDescriptor {
    uint64_t identifier;
    bool has_service_type;
    nxp_iot_ServiceType service_type;
    char *hostname;
    bool has_port;
    uint32_t port;
    bool has_timeout_ms;
    uint32_t timeout_ms;
    bool has_protocol;
    nxp_iot_ServiceProtocolType protocol;
    char *client_id;
    char *username;
    char *password;
    pb_bytes_array_t *client_certificate;
    pb_bytes_array_t *server_certificate;
    pb_callback_t client_key;
    char *customer_metadata_json;
    bool has_client_certificate_sss_ref;
    nxp_iot_SssObjectReference client_certificate_sss_ref;
    bool has_server_certificate_sss_ref;
    nxp_iot_SssObjectReference server_certificate_sss_ref;
    bool has_client_key_sss_ref;
    nxp_iot_SssObjectReference client_key_sss_ref;
    char *azure_id_scope;
    char *azure_registration_id;
    char *azure_global_device_endpoint;
/* @@protoc_insertion_point(struct:nxp_iot_ServiceDescriptor) */
} nxp_iot_ServiceDescriptor;

/* Default values for struct fields */

/* Initializer values for message structs */
#define nxp_iot_SssObjectReference_init_default  {false, _nxp_iot_EndpointType_MIN, false, 0, false, 0}
#define nxp_iot_ServiceDescriptor_init_default   {0, false, _nxp_iot_ServiceType_MIN, NULL, false, 0, false, 0, false, _nxp_iot_ServiceProtocolType_MIN, NULL, NULL, NULL, NULL, NULL, {{NULL}, NULL}, NULL, false, nxp_iot_SssObjectReference_init_default, false, nxp_iot_SssObjectReference_init_default, false, nxp_iot_SssObjectReference_init_default, NULL, NULL, NULL}
#define nxp_iot_SssObjectReference_init_zero     {false, _nxp_iot_EndpointType_MIN, false, 0, false, 0}
#define nxp_iot_ServiceDescriptor_init_zero      {0, false, _nxp_iot_ServiceType_MIN, NULL, false, 0, false, 0, false, _nxp_iot_ServiceProtocolType_MIN, NULL, NULL, NULL, NULL, NULL, {{NULL}, NULL}, NULL, false, nxp_iot_SssObjectReference_init_zero, false, nxp_iot_SssObjectReference_init_zero, false, nxp_iot_SssObjectReference_init_zero, NULL, NULL, NULL}

/* Field tags (for use in manual encoding/decoding) */
#define nxp_iot_SssObjectReference_type_tag      1
#define nxp_iot_SssObjectReference_endpoint_id_tag 2
#define nxp_iot_SssObjectReference_object_id_tag 3
#define nxp_iot_ServiceDescriptor_identifier_tag 1
#define nxp_iot_ServiceDescriptor_service_type_tag 2
#define nxp_iot_ServiceDescriptor_hostname_tag   10
#define nxp_iot_ServiceDescriptor_port_tag       11
#define nxp_iot_ServiceDescriptor_timeout_ms_tag 12
#define nxp_iot_ServiceDescriptor_protocol_tag   13
#define nxp_iot_ServiceDescriptor_client_id_tag  14
#define nxp_iot_ServiceDescriptor_username_tag   15
#define nxp_iot_ServiceDescriptor_password_tag   16
#define nxp_iot_ServiceDescriptor_client_certificate_tag 20
#define nxp_iot_ServiceDescriptor_server_certificate_tag 21
#define nxp_iot_ServiceDescriptor_client_key_tag 22
#define nxp_iot_ServiceDescriptor_client_certificate_sss_ref_tag 50
#define nxp_iot_ServiceDescriptor_server_certificate_sss_ref_tag 51
#define nxp_iot_ServiceDescriptor_client_key_sss_ref_tag 52
#define nxp_iot_ServiceDescriptor_customer_metadata_json_tag 30
#define nxp_iot_ServiceDescriptor_azure_id_scope_tag 100
#define nxp_iot_ServiceDescriptor_azure_registration_id_tag 101
#define nxp_iot_ServiceDescriptor_azure_global_device_endpoint_tag 102

/* Struct field encoding specification for nanopb */
extern const pb_field_t nxp_iot_SssObjectReference_fields[4];
extern const pb_field_t nxp_iot_ServiceDescriptor_fields[20];

/* Maximum encoded size of messages (where known) */
#define nxp_iot_SssObjectReference_size          14
/* nxp_iot_ServiceDescriptor_size depends on runtime parameters */

/* Message IDs (where set with "msgid" option) */
#ifdef PB_MSGID

#define SERVICEDESCRIPTOR_MESSAGES \


#endif

#ifdef __cplusplus
} /* extern "C" */
#endif
/* @@protoc_insertion_point(eof) */

#endif
