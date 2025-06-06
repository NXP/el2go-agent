/* Copyright 2022,2024 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */
/* Automatically generated nanopb constant definitions */
/* Generated by nanopb-0.3.9.8 at Fri Sep 20 08:31:23 2024. */

#include "ServiceDescriptor.pb.h"

/* @@protoc_insertion_point(includes) */
#if PB_PROTO_HEADER_VERSION != 30
#error Regenerate this file with the current version of nanopb generator.
#endif



const pb_field_t nxp_iot_SssObjectReference_fields[4] = {
    PB_FIELD(  1, UENUM   , OPTIONAL, STATIC  , FIRST, nxp_iot_SssObjectReference, type, type, 0),
    PB_FIELD(  2, UINT32  , OPTIONAL, STATIC  , OTHER, nxp_iot_SssObjectReference, endpoint_id, type, 0),
    PB_FIELD(  3, UINT32  , OPTIONAL, STATIC  , OTHER, nxp_iot_SssObjectReference, object_id, endpoint_id, 0),
    PB_LAST_FIELD
};

const pb_field_t nxp_iot_ServiceDescriptor_fields[20] = {
    PB_FIELD(  1, FIXED64 , REQUIRED, STATIC  , FIRST, nxp_iot_ServiceDescriptor, identifier, identifier, 0),
    PB_FIELD(  2, UENUM   , OPTIONAL, STATIC  , OTHER, nxp_iot_ServiceDescriptor, service_type, identifier, 0),
    PB_FIELD( 10, STRING  , OPTIONAL, POINTER , OTHER, nxp_iot_ServiceDescriptor, hostname, service_type, 0),
    PB_FIELD( 11, UINT32  , OPTIONAL, STATIC  , OTHER, nxp_iot_ServiceDescriptor, port, hostname, 0),
    PB_FIELD( 12, UINT32  , OPTIONAL, STATIC  , OTHER, nxp_iot_ServiceDescriptor, timeout_ms, port, 0),
    PB_FIELD( 13, UENUM   , OPTIONAL, STATIC  , OTHER, nxp_iot_ServiceDescriptor, protocol, timeout_ms, 0),
    PB_FIELD( 14, STRING  , OPTIONAL, POINTER , OTHER, nxp_iot_ServiceDescriptor, client_id, protocol, 0),
    PB_FIELD( 15, STRING  , OPTIONAL, POINTER , OTHER, nxp_iot_ServiceDescriptor, username, client_id, 0),
    PB_FIELD( 16, STRING  , OPTIONAL, POINTER , OTHER, nxp_iot_ServiceDescriptor, password, username, 0),
    PB_FIELD( 20, BYTES   , OPTIONAL, POINTER , OTHER, nxp_iot_ServiceDescriptor, client_certificate, password, 0),
    PB_FIELD( 21, BYTES   , OPTIONAL, POINTER , OTHER, nxp_iot_ServiceDescriptor, server_certificate, client_certificate, 0),
    PB_FIELD( 22, BYTES   , OPTIONAL, CALLBACK, OTHER, nxp_iot_ServiceDescriptor, client_key, server_certificate, 0),
    PB_FIELD( 30, STRING  , OPTIONAL, POINTER , OTHER, nxp_iot_ServiceDescriptor, customer_metadata_json, client_key, 0),
    PB_FIELD( 50, MESSAGE , OPTIONAL, STATIC  , OTHER, nxp_iot_ServiceDescriptor, client_certificate_sss_ref, customer_metadata_json, &nxp_iot_SssObjectReference_fields),
    PB_FIELD( 51, MESSAGE , OPTIONAL, STATIC  , OTHER, nxp_iot_ServiceDescriptor, server_certificate_sss_ref, client_certificate_sss_ref, &nxp_iot_SssObjectReference_fields),
    PB_FIELD( 52, MESSAGE , OPTIONAL, STATIC  , OTHER, nxp_iot_ServiceDescriptor, client_key_sss_ref, server_certificate_sss_ref, &nxp_iot_SssObjectReference_fields),
    PB_FIELD(100, STRING  , OPTIONAL, POINTER , OTHER, nxp_iot_ServiceDescriptor, azure_id_scope, client_key_sss_ref, 0),
    PB_FIELD(101, STRING  , OPTIONAL, POINTER , OTHER, nxp_iot_ServiceDescriptor, azure_registration_id, azure_id_scope, 0),
    PB_FIELD(102, STRING  , OPTIONAL, POINTER , OTHER, nxp_iot_ServiceDescriptor, azure_global_device_endpoint, azure_registration_id, 0),
    PB_LAST_FIELD
};


/* Check that field information fits in pb_field_t */
#if !defined(PB_FIELD_32BIT)
/* If you get an error here, it means that you need to define PB_FIELD_32BIT
 * compile-time option. You can do that in pb.h or on compiler command line.
 * 
 * The reason you need to do this is that some of your messages contain tag
 * numbers or field sizes that are larger than what can fit in 8 or 16 bit
 * field descriptors.
 */
PB_STATIC_ASSERT((pb_membersize(nxp_iot_ServiceDescriptor, client_certificate_sss_ref) < 65536 && pb_membersize(nxp_iot_ServiceDescriptor, server_certificate_sss_ref) < 65536 && pb_membersize(nxp_iot_ServiceDescriptor, client_key_sss_ref) < 65536), YOU_MUST_DEFINE_PB_FIELD_32BIT_FOR_MESSAGES_nxp_iot_SssObjectReference_nxp_iot_ServiceDescriptor)
#endif

#if !defined(PB_FIELD_16BIT) && !defined(PB_FIELD_32BIT)
/* If you get an error here, it means that you need to define PB_FIELD_16BIT
 * compile-time option. You can do that in pb.h or on compiler command line.
 * 
 * The reason you need to do this is that some of your messages contain tag
 * numbers or field sizes that are larger than what can fit in the default
 * 8 bit descriptors.
 */
PB_STATIC_ASSERT((pb_membersize(nxp_iot_ServiceDescriptor, client_certificate_sss_ref) < 256 && pb_membersize(nxp_iot_ServiceDescriptor, server_certificate_sss_ref) < 256 && pb_membersize(nxp_iot_ServiceDescriptor, client_key_sss_ref) < 256), YOU_MUST_DEFINE_PB_FIELD_16BIT_FOR_MESSAGES_nxp_iot_SssObjectReference_nxp_iot_ServiceDescriptor)
#endif


/* @@protoc_insertion_point(eof) */
