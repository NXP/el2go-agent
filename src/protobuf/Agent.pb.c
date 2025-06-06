/* Copyright 2022,2024 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */
/* Automatically generated nanopb constant definitions */
/* Generated by nanopb-0.3.9.8 at Fri Sep 20 08:31:18 2024. */

#include "Agent.pb.h"

/* @@protoc_insertion_point(includes) */
#if PB_PROTO_HEADER_VERSION != 30
#error Regenerate this file with the current version of nanopb generator.
#endif

const int32_t nxp_iot_AgentHelloResponse_communicationBufferSizeResponses_default = 1024;
const int32_t nxp_iot_AgentHelloResponse_communicationBufferSizeRequests_default = 1024;
const bool nxp_iot_AgentHelloResponse_useMultipleRequestsPerMessage_default = false;
const nxp_iot_ServiceDescriptorVersion nxp_iot_AgentHelloResponse_serviceDescriptorVersion_default = nxp_iot_ServiceDescriptorVersion_PROTOBUF;
const nxp_iot_ServiceDescriptorVersion nxp_iot_AgentAdditionalData_serviceDescriptorVersion_default = nxp_iot_ServiceDescriptorVersion_PROTOBUF;


const pb_field_t nxp_iot_EndpointInformation_fields[7] = {
    PB_FIELD(  1, UENUM   , OPTIONAL, STATIC  , FIRST, nxp_iot_EndpointInformation, type, type, 0),
    PB_FIELD(  2, UINT32  , OPTIONAL, STATIC  , OTHER, nxp_iot_EndpointInformation, endpointId, type, 0),
    PB_FIELD(  3, FIXED32 , OPTIONAL, STATIC  , OTHER, nxp_iot_EndpointInformation, version, endpointId, 0),
    PB_FIELD(  4, INT32   , OPTIONAL, STATIC  , OTHER, nxp_iot_EndpointInformation, state, version, 0),
    PB_FIELD(  5, BYTES   , OPTIONAL, STATIC  , OTHER, nxp_iot_EndpointInformation, additionalData, state, 0),
    PB_FIELD(  6, BYTES   , OPTIONAL, STATIC  , OTHER, nxp_iot_EndpointInformation, configurationState, additionalData, 0),
    PB_LAST_FIELD
};

const pb_field_t nxp_iot_AgentHelloRequest_fields[4] = {
    PB_FIELD(  1, FIXED32 , OPTIONAL, STATIC  , FIRST, nxp_iot_AgentHelloRequest, version, version, 0),
    PB_FIELD(  2, UENUM   , OPTIONAL, STATIC  , OTHER, nxp_iot_AgentHelloRequest, state, version, 0),
    PB_FIELD( 20, INT32   , OPTIONAL, STATIC  , OTHER, nxp_iot_AgentHelloRequest, communicationBufferSize, state, 0),
    PB_LAST_FIELD
};

const pb_field_t nxp_iot_AgentHelloResponse_fields[7] = {
    PB_FIELD(  1, FIXED32 , OPTIONAL, STATIC  , FIRST, nxp_iot_AgentHelloResponse, version, version, 0),
    PB_FIELD(  2, INT32   , OPTIONAL, STATIC  , OTHER, nxp_iot_AgentHelloResponse, communicationBufferSizeResponses, version, &nxp_iot_AgentHelloResponse_communicationBufferSizeResponses_default),
    PB_FIELD(  3, INT32   , OPTIONAL, STATIC  , OTHER, nxp_iot_AgentHelloResponse, communicationBufferSizeRequests, communicationBufferSizeResponses, &nxp_iot_AgentHelloResponse_communicationBufferSizeRequests_default),
    PB_FIELD(  4, UENUM   , OPTIONAL, STATIC  , OTHER, nxp_iot_AgentHelloResponse, serviceDescriptorVersion, communicationBufferSizeRequests, &nxp_iot_AgentHelloResponse_serviceDescriptorVersion_default),
    PB_FIELD(  5, BOOL    , OPTIONAL, STATIC  , OTHER, nxp_iot_AgentHelloResponse, useMultipleRequestsPerMessage, serviceDescriptorVersion, &nxp_iot_AgentHelloResponse_useMultipleRequestsPerMessage_default),
    PB_FIELD( 10, MESSAGE , REPEATED, STATIC  , OTHER, nxp_iot_AgentHelloResponse, endpoints, useMultipleRequestsPerMessage, &nxp_iot_EndpointInformation_fields),
    PB_LAST_FIELD
};

const pb_field_t nxp_iot_AgentAdditionalData_fields[4] = {
    PB_FIELD(  1, UENUM   , OPTIONAL, STATIC  , FIRST, nxp_iot_AgentAdditionalData, serviceDescriptorVersion, serviceDescriptorVersion, &nxp_iot_AgentAdditionalData_serviceDescriptorVersion_default),
    PB_FIELD(  2, BOOL    , OPTIONAL, STATIC  , OTHER, nxp_iot_AgentAdditionalData, requestCrl, serviceDescriptorVersion, 0),
    PB_FIELD(  3, BOOL    , OPTIONAL, STATIC  , OTHER, nxp_iot_AgentAdditionalData, sendRequestMetadata, requestCrl, 0),
    PB_LAST_FIELD
};

const pb_field_t nxp_iot_AgentClaimStatus_fields[3] = {
    PB_FIELD(  1, UENUM   , OPTIONAL, STATIC  , FIRST, nxp_iot_AgentClaimStatus, status, status, 0),
    PB_FIELD(  2, MESSAGE , REPEATED, POINTER , OTHER, nxp_iot_AgentClaimStatus, details, status, &nxp_iot_AgentClaimStatus_DetailedClaimStatus_fields),
    PB_LAST_FIELD
};

const pb_field_t nxp_iot_AgentClaimStatus_DetailedClaimStatus_fields[3] = {
    PB_FIELD(  1, UENUM   , OPTIONAL, STATIC  , FIRST, nxp_iot_AgentClaimStatus_DetailedClaimStatus, status, status, 0),
    PB_FIELD(  2, UINT32  , OPTIONAL, STATIC  , OTHER, nxp_iot_AgentClaimStatus_DetailedClaimStatus, endpointId, status, 0),
    PB_LAST_FIELD
};

const pb_field_t nxp_iot_AgentRtpStatus_fields[3] = {
    PB_FIELD(  1, UENUM   , OPTIONAL, STATIC  , FIRST, nxp_iot_AgentRtpStatus, status, status, 0),
    PB_FIELD(  2, MESSAGE , REPEATED, POINTER , OTHER, nxp_iot_AgentRtpStatus, details, status, &nxp_iot_AgentRtpStatus_RtpObjectStatus_fields),
    PB_LAST_FIELD
};

const pb_field_t nxp_iot_AgentRtpStatus_RtpObjectStatus_fields[4] = {
    PB_FIELD(  1, UENUM   , OPTIONAL, STATIC  , FIRST, nxp_iot_AgentRtpStatus_RtpObjectStatus, status, status, 0),
    PB_FIELD(  2, UINT32  , OPTIONAL, STATIC  , OTHER, nxp_iot_AgentRtpStatus_RtpObjectStatus, endpointId, status, 0),
    PB_FIELD(  3, UINT32  , OPTIONAL, STATIC  , OTHER, nxp_iot_AgentRtpStatus_RtpObjectStatus, objectId, endpointId, 0),
    PB_LAST_FIELD
};

const pb_field_t nxp_iot_AgentCspStatus_fields[3] = {
    PB_FIELD(  1, UENUM   , OPTIONAL, STATIC  , FIRST, nxp_iot_AgentCspStatus, status, status, 0),
    PB_FIELD(  2, MESSAGE , REPEATED, POINTER , OTHER, nxp_iot_AgentCspStatus, details, status, &nxp_iot_AgentCspStatus_CspServiceStatus_fields),
    PB_LAST_FIELD
};

const pb_field_t nxp_iot_AgentCspStatus_CspServiceStatus_fields[4] = {
    PB_FIELD(  1, UENUM   , OPTIONAL, STATIC  , FIRST, nxp_iot_AgentCspStatus_CspServiceStatus, status, status, 0),
    PB_FIELD(  2, UINT32  , OPTIONAL, STATIC  , OTHER, nxp_iot_AgentCspStatus_CspServiceStatus, endpointId, status, 0),
    PB_FIELD(  3, UINT64  , OPTIONAL, STATIC  , OTHER, nxp_iot_AgentCspStatus_CspServiceStatus, serviceId, endpointId, 0),
    PB_LAST_FIELD
};

const pb_field_t nxp_iot_UpdateStatusReport_fields[6] = {
    PB_FIELD(  1, UENUM   , OPTIONAL, STATIC  , FIRST, nxp_iot_UpdateStatusReport, status, status, 0),
    PB_FIELD(  2, MESSAGE , OPTIONAL, STATIC  , OTHER, nxp_iot_UpdateStatusReport, claimStatus, status, &nxp_iot_AgentClaimStatus_fields),
    PB_FIELD(  3, MESSAGE , OPTIONAL, STATIC  , OTHER, nxp_iot_UpdateStatusReport, rtpStatus, claimStatus, &nxp_iot_AgentRtpStatus_fields),
    PB_FIELD(  4, MESSAGE , OPTIONAL, STATIC  , OTHER, nxp_iot_UpdateStatusReport, cspStatus, rtpStatus, &nxp_iot_AgentCspStatus_fields),
    PB_FIELD(  5, STRING  , OPTIONAL, STATIC  , OTHER, nxp_iot_UpdateStatusReport, correlationId, cspStatus, 0),
    PB_LAST_FIELD
};

const pb_field_t nxp_iot_AgentGoodbyeRequest_fields[2] = {
    PB_FIELD(  1, MESSAGE , OPTIONAL, STATIC  , FIRST, nxp_iot_AgentGoodbyeRequest, status, status, &nxp_iot_UpdateStatusReport_fields),
    PB_LAST_FIELD
};

const pb_field_t nxp_iot_AgentCrlRequest_fields[2] = {
    PB_FIELD(  1, BYTES   , OPTIONAL, POINTER , FIRST, nxp_iot_AgentCrlRequest, crl, crl, 0),
    PB_LAST_FIELD
};

const pb_field_t nxp_iot_AgentCrlResponse_fields[2] = {
    PB_FIELD(  1, FIXED32 , OPTIONAL, STATIC  , FIRST, nxp_iot_AgentCrlResponse, error, error, 0),
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
PB_STATIC_ASSERT((pb_membersize(nxp_iot_AgentHelloResponse, endpoints[0]) < 65536 && pb_membersize(nxp_iot_UpdateStatusReport, claimStatus) < 65536 && pb_membersize(nxp_iot_UpdateStatusReport, rtpStatus) < 65536 && pb_membersize(nxp_iot_UpdateStatusReport, cspStatus) < 65536 && pb_membersize(nxp_iot_AgentGoodbyeRequest, status) < 65536), YOU_MUST_DEFINE_PB_FIELD_32BIT_FOR_MESSAGES_nxp_iot_EndpointInformation_nxp_iot_AgentHelloRequest_nxp_iot_AgentHelloResponse_nxp_iot_AgentAdditionalData_nxp_iot_AgentClaimStatus_nxp_iot_AgentClaimStatus_DetailedClaimStatus_nxp_iot_AgentRtpStatus_nxp_iot_AgentRtpStatus_RtpObjectStatus_nxp_iot_AgentCspStatus_nxp_iot_AgentCspStatus_CspServiceStatus_nxp_iot_UpdateStatusReport_nxp_iot_AgentGoodbyeRequest_nxp_iot_AgentCrlRequest_nxp_iot_AgentCrlResponse)
#endif

#if !defined(PB_FIELD_16BIT) && !defined(PB_FIELD_32BIT)
/* If you get an error here, it means that you need to define PB_FIELD_16BIT
 * compile-time option. You can do that in pb.h or on compiler command line.
 * 
 * The reason you need to do this is that some of your messages contain tag
 * numbers or field sizes that are larger than what can fit in the default
 * 8 bit descriptors.
 */
PB_STATIC_ASSERT((pb_membersize(nxp_iot_AgentHelloResponse, endpoints[0]) < 256 && pb_membersize(nxp_iot_UpdateStatusReport, claimStatus) < 256 && pb_membersize(nxp_iot_UpdateStatusReport, rtpStatus) < 256 && pb_membersize(nxp_iot_UpdateStatusReport, cspStatus) < 256 && pb_membersize(nxp_iot_AgentGoodbyeRequest, status) < 256), YOU_MUST_DEFINE_PB_FIELD_16BIT_FOR_MESSAGES_nxp_iot_EndpointInformation_nxp_iot_AgentHelloRequest_nxp_iot_AgentHelloResponse_nxp_iot_AgentAdditionalData_nxp_iot_AgentClaimStatus_nxp_iot_AgentClaimStatus_DetailedClaimStatus_nxp_iot_AgentRtpStatus_nxp_iot_AgentRtpStatus_RtpObjectStatus_nxp_iot_AgentCspStatus_nxp_iot_AgentCspStatus_CspServiceStatus_nxp_iot_UpdateStatusReport_nxp_iot_AgentGoodbyeRequest_nxp_iot_AgentCrlRequest_nxp_iot_AgentCrlResponse)
#endif


/* @@protoc_insertion_point(eof) */
