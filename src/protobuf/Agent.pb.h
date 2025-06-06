/* Copyright 2022,2024 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */
/* Automatically generated nanopb header */
/* Generated by nanopb-0.3.9.8 at Fri Sep 20 08:31:18 2024. */

#ifndef PB_NXP_IOT_AGENT_PB_H_INCLUDED
#define PB_NXP_IOT_AGENT_PB_H_INCLUDED
#include <pb.h>

#include "Types.pb.h"

/* @@protoc_insertion_point(includes) */
#if PB_PROTO_HEADER_VERSION != 30
#error Regenerate this file with the current version of nanopb generator.
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Enum definitions */
typedef enum _nxp_iot_ServiceDescriptorVersion {
    nxp_iot_ServiceDescriptorVersion_C_STRUCTURE_01 = 0,
    nxp_iot_ServiceDescriptorVersion_PROTOBUF = 10
} nxp_iot_ServiceDescriptorVersion;
#define _nxp_iot_ServiceDescriptorVersion_MIN nxp_iot_ServiceDescriptorVersion_C_STRUCTURE_01
#define _nxp_iot_ServiceDescriptorVersion_MAX nxp_iot_ServiceDescriptorVersion_PROTOBUF
#define _nxp_iot_ServiceDescriptorVersion_ARRAYSIZE ((nxp_iot_ServiceDescriptorVersion)(nxp_iot_ServiceDescriptorVersion_PROTOBUF+1))

typedef enum _nxp_iot_AgentHelloRequest_DeviceState {
    nxp_iot_AgentHelloRequest_DeviceState_OK = 0,
    nxp_iot_AgentHelloRequest_DeviceState_CLOUD_ERROR = 10,
    nxp_iot_AgentHelloRequest_DeviceState_FORCE_UPDATE = 100
} nxp_iot_AgentHelloRequest_DeviceState;
#define _nxp_iot_AgentHelloRequest_DeviceState_MIN nxp_iot_AgentHelloRequest_DeviceState_OK
#define _nxp_iot_AgentHelloRequest_DeviceState_MAX nxp_iot_AgentHelloRequest_DeviceState_FORCE_UPDATE
#define _nxp_iot_AgentHelloRequest_DeviceState_ARRAYSIZE ((nxp_iot_AgentHelloRequest_DeviceState)(nxp_iot_AgentHelloRequest_DeviceState_FORCE_UPDATE+1))

typedef enum _nxp_iot_AgentClaimStatus_ClaimStatus {
    nxp_iot_AgentClaimStatus_ClaimStatus_UNKNOWN = 0,
    nxp_iot_AgentClaimStatus_ClaimStatus_SUCCESS = 1,
    nxp_iot_AgentClaimStatus_ClaimStatus_ERR_NOT_FOUND = 16,
    nxp_iot_AgentClaimStatus_ClaimStatus_ERR_WRONG_PRODUCT_TYPE = 17,
    nxp_iot_AgentClaimStatus_ClaimStatus_ERR_CLAIM_CODE_REVOKED = 19,
    nxp_iot_AgentClaimStatus_ClaimStatus_ERR_CLAIM_CODE_LIMIT_REACHED = 20,
    nxp_iot_AgentClaimStatus_ClaimStatus_ERR_CLAIM_CODE_REUSE_PROHIBITED = 21,
    nxp_iot_AgentClaimStatus_ClaimStatus_ERR_CLAIM_CODE_READ = 22,
    nxp_iot_AgentClaimStatus_ClaimStatus_ERR_CLAIM_CODE_POLICIES = 23,
    nxp_iot_AgentClaimStatus_ClaimStatus_ERR_CLAIM_CODE_TYPE = 24,
    nxp_iot_AgentClaimStatus_ClaimStatus_ERR_CLAIM_CODE_FORMAT = 25,
    nxp_iot_AgentClaimStatus_ClaimStatus_ERR_CLAIM_FAILED = 64,
    nxp_iot_AgentClaimStatus_ClaimStatus_ERR_INTERNAL = 80,
    nxp_iot_AgentClaimStatus_ClaimStatus_ERR_TIMEOUT = 81
} nxp_iot_AgentClaimStatus_ClaimStatus;
#define _nxp_iot_AgentClaimStatus_ClaimStatus_MIN nxp_iot_AgentClaimStatus_ClaimStatus_UNKNOWN
#define _nxp_iot_AgentClaimStatus_ClaimStatus_MAX nxp_iot_AgentClaimStatus_ClaimStatus_ERR_TIMEOUT
#define _nxp_iot_AgentClaimStatus_ClaimStatus_ARRAYSIZE ((nxp_iot_AgentClaimStatus_ClaimStatus)(nxp_iot_AgentClaimStatus_ClaimStatus_ERR_TIMEOUT+1))

typedef enum _nxp_iot_AgentRtpStatus_RtpStatus {
    nxp_iot_AgentRtpStatus_RtpStatus_UNKNOWN = 0,
    nxp_iot_AgentRtpStatus_RtpStatus_SUCCESS = 1,
    nxp_iot_AgentRtpStatus_RtpStatus_SUCCESS_NO_CHANGE = 2,
    nxp_iot_AgentRtpStatus_RtpStatus_ERR_OBJECT_ATTRIBUTES_READ_FAILED = 16,
    nxp_iot_AgentRtpStatus_RtpStatus_ERR_OBJECT_DELETE_FAILED = 17,
    nxp_iot_AgentRtpStatus_RtpStatus_ERR_OBJECT_WRITE_FAILED = 18,
    nxp_iot_AgentRtpStatus_RtpStatus_ERR_DEFECTIVE = 19,
    nxp_iot_AgentRtpStatus_RtpStatus_ERR_CURVE_INSTALLATION_FAILED = 20,
    nxp_iot_AgentRtpStatus_RtpStatus_ERR_RTP_FAILED = 64,
    nxp_iot_AgentRtpStatus_RtpStatus_ERR_INTERNAL = 80,
    nxp_iot_AgentRtpStatus_RtpStatus_ERR_TIMEOUT = 81
} nxp_iot_AgentRtpStatus_RtpStatus;
#define _nxp_iot_AgentRtpStatus_RtpStatus_MIN nxp_iot_AgentRtpStatus_RtpStatus_UNKNOWN
#define _nxp_iot_AgentRtpStatus_RtpStatus_MAX nxp_iot_AgentRtpStatus_RtpStatus_ERR_TIMEOUT
#define _nxp_iot_AgentRtpStatus_RtpStatus_ARRAYSIZE ((nxp_iot_AgentRtpStatus_RtpStatus)(nxp_iot_AgentRtpStatus_RtpStatus_ERR_TIMEOUT+1))

typedef enum _nxp_iot_AgentCspStatus_CspStatus {
    nxp_iot_AgentCspStatus_CspStatus_UNKNOWN = 0,
    nxp_iot_AgentCspStatus_CspStatus_SUCCESS = 1,
    nxp_iot_AgentCspStatus_CspStatus_SUCCESS_NO_CHANGE = 2,
    nxp_iot_AgentCspStatus_CspStatus_SUCCESS_REVOKED = 3,
    nxp_iot_AgentCspStatus_CspStatus_ERR_KEY_SLOT_OCCUPIED = 16,
    nxp_iot_AgentCspStatus_CspStatus_ERR_KEY_GENERATION_FAILED = 17,
    nxp_iot_AgentCspStatus_CspStatus_ERR_KEY_READOUT_FAILED = 18,
    nxp_iot_AgentCspStatus_CspStatus_ERR_MEMORY_READ_FAILED = 19,
    nxp_iot_AgentCspStatus_CspStatus_ERR_MEMORY_ALLOCATION_FAILED = 20,
    nxp_iot_AgentCspStatus_CspStatus_ERR_SERVICE_DESCRIPTOR_WRITE_FAILED = 21,
    nxp_iot_AgentCspStatus_CspStatus_ERR_MEMORY_COMMIT_FAILED = 23,
    nxp_iot_AgentCspStatus_CspStatus_ERR_DEFECTIVE = 22,
    nxp_iot_AgentCspStatus_CspStatus_ERR_CSP_FAILED = 64,
    nxp_iot_AgentCspStatus_CspStatus_ERR_INTERNAL = 80,
    nxp_iot_AgentCspStatus_CspStatus_ERR_TIMEOUT = 81
} nxp_iot_AgentCspStatus_CspStatus;
#define _nxp_iot_AgentCspStatus_CspStatus_MIN nxp_iot_AgentCspStatus_CspStatus_UNKNOWN
#define _nxp_iot_AgentCspStatus_CspStatus_MAX nxp_iot_AgentCspStatus_CspStatus_ERR_TIMEOUT
#define _nxp_iot_AgentCspStatus_CspStatus_ARRAYSIZE ((nxp_iot_AgentCspStatus_CspStatus)(nxp_iot_AgentCspStatus_CspStatus_ERR_TIMEOUT+1))

typedef enum _nxp_iot_UpdateStatusReport_UpdateStatus {
    nxp_iot_UpdateStatusReport_UpdateStatus_UNKNOWN = 0,
    nxp_iot_UpdateStatusReport_UpdateStatus_SUCCESS = 1,
    nxp_iot_UpdateStatusReport_UpdateStatus_ERR_ENCODING = 16,
    nxp_iot_UpdateStatusReport_UpdateStatus_ERR_PROTOCOL = 17,
    nxp_iot_UpdateStatusReport_UpdateStatus_ERR_MEMORY_READ = 18,
    nxp_iot_UpdateStatusReport_UpdateStatus_ERR_MEMORY_WRITE = 19,
    nxp_iot_UpdateStatusReport_UpdateStatus_ERR_SSS_COMMUNICATION = 20,
    nxp_iot_UpdateStatusReport_UpdateStatus_ERR_SSS_VERSION = 21,
    nxp_iot_UpdateStatusReport_UpdateStatus_ERR_SSS_SECURE_CHANNEL = 22,
    nxp_iot_UpdateStatusReport_UpdateStatus_ERR_CONFIGURATION = 32,
    nxp_iot_UpdateStatusReport_UpdateStatus_ERR_CONFIGURATION_TOO_MANY_DATASTORES = 33,
    nxp_iot_UpdateStatusReport_UpdateStatus_ERR_CONFIGURATION_TOO_MANY_KEYSTORES = 34,
    nxp_iot_UpdateStatusReport_UpdateStatus_ERR_CONFIGURATION_SNI_MISSING = 50,
    nxp_iot_UpdateStatusReport_UpdateStatus_ERR_CONFIGURATION_SNI_INVALID = 51,
    nxp_iot_UpdateStatusReport_UpdateStatus_ERR_CONNECTION_QUOTA_EXCEEDED = 52,
    nxp_iot_UpdateStatusReport_UpdateStatus_ERR_DEVICE_NOT_WHITELISTED = 53,
    nxp_iot_UpdateStatusReport_UpdateStatus_ERR_UPDATE_FAILED = 64,
    nxp_iot_UpdateStatusReport_UpdateStatus_ERR_INTERNAL = 80,
    nxp_iot_UpdateStatusReport_UpdateStatus_ERR_TIMEOUT = 81
} nxp_iot_UpdateStatusReport_UpdateStatus;
#define _nxp_iot_UpdateStatusReport_UpdateStatus_MIN nxp_iot_UpdateStatusReport_UpdateStatus_UNKNOWN
#define _nxp_iot_UpdateStatusReport_UpdateStatus_MAX nxp_iot_UpdateStatusReport_UpdateStatus_ERR_TIMEOUT
#define _nxp_iot_UpdateStatusReport_UpdateStatus_ARRAYSIZE ((nxp_iot_UpdateStatusReport_UpdateStatus)(nxp_iot_UpdateStatusReport_UpdateStatus_ERR_TIMEOUT+1))

/* Struct definitions */
typedef struct _nxp_iot_AgentCrlRequest {
    pb_bytes_array_t *crl;
/* @@protoc_insertion_point(struct:nxp_iot_AgentCrlRequest) */
} nxp_iot_AgentCrlRequest;

typedef struct _nxp_iot_AgentAdditionalData {
    bool has_serviceDescriptorVersion;
    nxp_iot_ServiceDescriptorVersion serviceDescriptorVersion;
    bool has_requestCrl;
    bool requestCrl;
    bool has_sendRequestMetadata;
    bool sendRequestMetadata;
/* @@protoc_insertion_point(struct:nxp_iot_AgentAdditionalData) */
} nxp_iot_AgentAdditionalData;

typedef struct _nxp_iot_AgentClaimStatus {
    bool has_status;
    nxp_iot_AgentClaimStatus_ClaimStatus status;
    pb_size_t details_count;
    struct _nxp_iot_AgentClaimStatus_DetailedClaimStatus *details;
/* @@protoc_insertion_point(struct:nxp_iot_AgentClaimStatus) */
} nxp_iot_AgentClaimStatus;

typedef struct _nxp_iot_AgentClaimStatus_DetailedClaimStatus {
    bool has_status;
    nxp_iot_AgentClaimStatus_ClaimStatus status;
    bool has_endpointId;
    uint32_t endpointId;
/* @@protoc_insertion_point(struct:nxp_iot_AgentClaimStatus_DetailedClaimStatus) */
} nxp_iot_AgentClaimStatus_DetailedClaimStatus;

typedef struct _nxp_iot_AgentCrlResponse {
    bool has_error;
    uint32_t error;
/* @@protoc_insertion_point(struct:nxp_iot_AgentCrlResponse) */
} nxp_iot_AgentCrlResponse;

typedef struct _nxp_iot_AgentCspStatus {
    bool has_status;
    nxp_iot_AgentCspStatus_CspStatus status;
    pb_size_t details_count;
    struct _nxp_iot_AgentCspStatus_CspServiceStatus *details;
/* @@protoc_insertion_point(struct:nxp_iot_AgentCspStatus) */
} nxp_iot_AgentCspStatus;

typedef struct _nxp_iot_AgentCspStatus_CspServiceStatus {
    bool has_status;
    nxp_iot_AgentCspStatus_CspStatus status;
    bool has_endpointId;
    uint32_t endpointId;
    bool has_serviceId;
    uint64_t serviceId;
/* @@protoc_insertion_point(struct:nxp_iot_AgentCspStatus_CspServiceStatus) */
} nxp_iot_AgentCspStatus_CspServiceStatus;

typedef struct _nxp_iot_AgentHelloRequest {
    bool has_version;
    uint32_t version;
    bool has_state;
    nxp_iot_AgentHelloRequest_DeviceState state;
    bool has_communicationBufferSize;
    int32_t communicationBufferSize;
/* @@protoc_insertion_point(struct:nxp_iot_AgentHelloRequest) */
} nxp_iot_AgentHelloRequest;

typedef struct _nxp_iot_AgentRtpStatus {
    bool has_status;
    nxp_iot_AgentRtpStatus_RtpStatus status;
    pb_size_t details_count;
    struct _nxp_iot_AgentRtpStatus_RtpObjectStatus *details;
/* @@protoc_insertion_point(struct:nxp_iot_AgentRtpStatus) */
} nxp_iot_AgentRtpStatus;

typedef struct _nxp_iot_AgentRtpStatus_RtpObjectStatus {
    bool has_status;
    nxp_iot_AgentRtpStatus_RtpStatus status;
    bool has_endpointId;
    uint32_t endpointId;
    bool has_objectId;
    uint32_t objectId;
/* @@protoc_insertion_point(struct:nxp_iot_AgentRtpStatus_RtpObjectStatus) */
} nxp_iot_AgentRtpStatus_RtpObjectStatus;

typedef PB_BYTES_ARRAY_T(64) nxp_iot_EndpointInformation_additionalData_t;
typedef PB_BYTES_ARRAY_T(64) nxp_iot_EndpointInformation_configurationState_t;
typedef struct _nxp_iot_EndpointInformation {
    bool has_type;
    nxp_iot_EndpointType type;
    bool has_endpointId;
    uint32_t endpointId;
    bool has_version;
    uint32_t version;
    bool has_state;
    int32_t state;
    bool has_additionalData;
    nxp_iot_EndpointInformation_additionalData_t additionalData;
    bool has_configurationState;
    nxp_iot_EndpointInformation_configurationState_t configurationState;
/* @@protoc_insertion_point(struct:nxp_iot_EndpointInformation) */
} nxp_iot_EndpointInformation;

typedef struct _nxp_iot_AgentHelloResponse {
    bool has_version;
    uint32_t version;
    bool has_communicationBufferSizeResponses;
    int32_t communicationBufferSizeResponses;
    bool has_communicationBufferSizeRequests;
    int32_t communicationBufferSizeRequests;
    bool has_serviceDescriptorVersion;
    nxp_iot_ServiceDescriptorVersion serviceDescriptorVersion;
    bool has_useMultipleRequestsPerMessage;
    bool useMultipleRequestsPerMessage;
    pb_size_t endpoints_count;
    nxp_iot_EndpointInformation endpoints[5];
/* @@protoc_insertion_point(struct:nxp_iot_AgentHelloResponse) */
} nxp_iot_AgentHelloResponse;

typedef struct _nxp_iot_UpdateStatusReport {
    bool has_status;
    nxp_iot_UpdateStatusReport_UpdateStatus status;
    bool has_claimStatus;
    nxp_iot_AgentClaimStatus claimStatus;
    bool has_rtpStatus;
    nxp_iot_AgentRtpStatus rtpStatus;
    bool has_cspStatus;
    nxp_iot_AgentCspStatus cspStatus;
    bool has_correlationId;
    char correlationId[37];
/* @@protoc_insertion_point(struct:nxp_iot_UpdateStatusReport) */
} nxp_iot_UpdateStatusReport;

typedef struct _nxp_iot_AgentGoodbyeRequest {
    bool has_status;
    nxp_iot_UpdateStatusReport status;
/* @@protoc_insertion_point(struct:nxp_iot_AgentGoodbyeRequest) */
} nxp_iot_AgentGoodbyeRequest;

/* Default values for struct fields */
extern const int32_t nxp_iot_AgentHelloResponse_communicationBufferSizeResponses_default;
extern const int32_t nxp_iot_AgentHelloResponse_communicationBufferSizeRequests_default;
extern const bool nxp_iot_AgentHelloResponse_useMultipleRequestsPerMessage_default;
extern const nxp_iot_ServiceDescriptorVersion nxp_iot_AgentHelloResponse_serviceDescriptorVersion_default;
extern const nxp_iot_ServiceDescriptorVersion nxp_iot_AgentAdditionalData_serviceDescriptorVersion_default;

/* Initializer values for message structs */
#define nxp_iot_EndpointInformation_init_default {false, _nxp_iot_EndpointType_MIN, false, 0, false, 0, false, 0, false, {0, {0}}, false, {0, {0}}}
#define nxp_iot_AgentHelloRequest_init_default   {false, 0, false, _nxp_iot_AgentHelloRequest_DeviceState_MIN, false, 0}
#define nxp_iot_AgentHelloResponse_init_default  {false, 0, false, 1024, false, 1024, false, nxp_iot_ServiceDescriptorVersion_PROTOBUF, false, false, 0, {nxp_iot_EndpointInformation_init_default, nxp_iot_EndpointInformation_init_default, nxp_iot_EndpointInformation_init_default, nxp_iot_EndpointInformation_init_default, nxp_iot_EndpointInformation_init_default}}
#define nxp_iot_AgentAdditionalData_init_default {false, nxp_iot_ServiceDescriptorVersion_PROTOBUF, false, 0, false, 0}
#define nxp_iot_AgentClaimStatus_init_default    {false, _nxp_iot_AgentClaimStatus_ClaimStatus_MIN, 0, NULL}
#define nxp_iot_AgentClaimStatus_DetailedClaimStatus_init_default {false, _nxp_iot_AgentClaimStatus_ClaimStatus_MIN, false, 0}
#define nxp_iot_AgentRtpStatus_init_default      {false, _nxp_iot_AgentRtpStatus_RtpStatus_MIN, 0, NULL}
#define nxp_iot_AgentRtpStatus_RtpObjectStatus_init_default {false, _nxp_iot_AgentRtpStatus_RtpStatus_MIN, false, 0, false, 0}
#define nxp_iot_AgentCspStatus_init_default      {false, _nxp_iot_AgentCspStatus_CspStatus_MIN, 0, NULL}
#define nxp_iot_AgentCspStatus_CspServiceStatus_init_default {false, _nxp_iot_AgentCspStatus_CspStatus_MIN, false, 0, false, 0}
#define nxp_iot_UpdateStatusReport_init_default  {false, _nxp_iot_UpdateStatusReport_UpdateStatus_MIN, false, nxp_iot_AgentClaimStatus_init_default, false, nxp_iot_AgentRtpStatus_init_default, false, nxp_iot_AgentCspStatus_init_default, false, ""}
#define nxp_iot_AgentGoodbyeRequest_init_default {false, nxp_iot_UpdateStatusReport_init_default}
#define nxp_iot_AgentCrlRequest_init_default     {NULL}
#define nxp_iot_AgentCrlResponse_init_default    {false, 0}
#define nxp_iot_EndpointInformation_init_zero    {false, _nxp_iot_EndpointType_MIN, false, 0, false, 0, false, 0, false, {0, {0}}, false, {0, {0}}}
#define nxp_iot_AgentHelloRequest_init_zero      {false, 0, false, _nxp_iot_AgentHelloRequest_DeviceState_MIN, false, 0}
#define nxp_iot_AgentHelloResponse_init_zero     {false, 0, false, 0, false, 0, false, _nxp_iot_ServiceDescriptorVersion_MIN, false, 0, 0, {nxp_iot_EndpointInformation_init_zero, nxp_iot_EndpointInformation_init_zero, nxp_iot_EndpointInformation_init_zero, nxp_iot_EndpointInformation_init_zero, nxp_iot_EndpointInformation_init_zero}}
#define nxp_iot_AgentAdditionalData_init_zero    {false, _nxp_iot_ServiceDescriptorVersion_MIN, false, 0, false, 0}
#define nxp_iot_AgentClaimStatus_init_zero       {false, _nxp_iot_AgentClaimStatus_ClaimStatus_MIN, 0, NULL}
#define nxp_iot_AgentClaimStatus_DetailedClaimStatus_init_zero {false, _nxp_iot_AgentClaimStatus_ClaimStatus_MIN, false, 0}
#define nxp_iot_AgentRtpStatus_init_zero         {false, _nxp_iot_AgentRtpStatus_RtpStatus_MIN, 0, NULL}
#define nxp_iot_AgentRtpStatus_RtpObjectStatus_init_zero {false, _nxp_iot_AgentRtpStatus_RtpStatus_MIN, false, 0, false, 0}
#define nxp_iot_AgentCspStatus_init_zero         {false, _nxp_iot_AgentCspStatus_CspStatus_MIN, 0, NULL}
#define nxp_iot_AgentCspStatus_CspServiceStatus_init_zero {false, _nxp_iot_AgentCspStatus_CspStatus_MIN, false, 0, false, 0}
#define nxp_iot_UpdateStatusReport_init_zero     {false, _nxp_iot_UpdateStatusReport_UpdateStatus_MIN, false, nxp_iot_AgentClaimStatus_init_zero, false, nxp_iot_AgentRtpStatus_init_zero, false, nxp_iot_AgentCspStatus_init_zero, false, ""}
#define nxp_iot_AgentGoodbyeRequest_init_zero    {false, nxp_iot_UpdateStatusReport_init_zero}
#define nxp_iot_AgentCrlRequest_init_zero        {NULL}
#define nxp_iot_AgentCrlResponse_init_zero       {false, 0}

/* Field tags (for use in manual encoding/decoding) */
#define nxp_iot_AgentCrlRequest_crl_tag          1
#define nxp_iot_AgentAdditionalData_serviceDescriptorVersion_tag 1
#define nxp_iot_AgentAdditionalData_requestCrl_tag 2
#define nxp_iot_AgentAdditionalData_sendRequestMetadata_tag 3
#define nxp_iot_AgentClaimStatus_status_tag      1
#define nxp_iot_AgentClaimStatus_details_tag     2
#define nxp_iot_AgentClaimStatus_DetailedClaimStatus_status_tag 1
#define nxp_iot_AgentClaimStatus_DetailedClaimStatus_endpointId_tag 2
#define nxp_iot_AgentCrlResponse_error_tag       1
#define nxp_iot_AgentCspStatus_status_tag        1
#define nxp_iot_AgentCspStatus_details_tag       2
#define nxp_iot_AgentCspStatus_CspServiceStatus_status_tag 1
#define nxp_iot_AgentCspStatus_CspServiceStatus_endpointId_tag 2
#define nxp_iot_AgentCspStatus_CspServiceStatus_serviceId_tag 3
#define nxp_iot_AgentHelloRequest_version_tag    1
#define nxp_iot_AgentHelloRequest_state_tag      2
#define nxp_iot_AgentHelloRequest_communicationBufferSize_tag 20
#define nxp_iot_AgentRtpStatus_status_tag        1
#define nxp_iot_AgentRtpStatus_details_tag       2
#define nxp_iot_AgentRtpStatus_RtpObjectStatus_status_tag 1
#define nxp_iot_AgentRtpStatus_RtpObjectStatus_endpointId_tag 2
#define nxp_iot_AgentRtpStatus_RtpObjectStatus_objectId_tag 3
#define nxp_iot_EndpointInformation_type_tag     1
#define nxp_iot_EndpointInformation_endpointId_tag 2
#define nxp_iot_EndpointInformation_version_tag  3
#define nxp_iot_EndpointInformation_state_tag    4
#define nxp_iot_EndpointInformation_additionalData_tag 5
#define nxp_iot_EndpointInformation_configurationState_tag 6
#define nxp_iot_AgentHelloResponse_version_tag   1
#define nxp_iot_AgentHelloResponse_communicationBufferSizeResponses_tag 2
#define nxp_iot_AgentHelloResponse_communicationBufferSizeRequests_tag 3
#define nxp_iot_AgentHelloResponse_useMultipleRequestsPerMessage_tag 5
#define nxp_iot_AgentHelloResponse_serviceDescriptorVersion_tag 4
#define nxp_iot_AgentHelloResponse_endpoints_tag 10
#define nxp_iot_UpdateStatusReport_status_tag    1
#define nxp_iot_UpdateStatusReport_claimStatus_tag 2
#define nxp_iot_UpdateStatusReport_rtpStatus_tag 3
#define nxp_iot_UpdateStatusReport_cspStatus_tag 4
#define nxp_iot_UpdateStatusReport_correlationId_tag 5
#define nxp_iot_AgentGoodbyeRequest_status_tag   1

/* Struct field encoding specification for nanopb */
extern const pb_field_t nxp_iot_EndpointInformation_fields[7];
extern const pb_field_t nxp_iot_AgentHelloRequest_fields[4];
extern const pb_field_t nxp_iot_AgentHelloResponse_fields[7];
extern const pb_field_t nxp_iot_AgentAdditionalData_fields[4];
extern const pb_field_t nxp_iot_AgentClaimStatus_fields[3];
extern const pb_field_t nxp_iot_AgentClaimStatus_DetailedClaimStatus_fields[3];
extern const pb_field_t nxp_iot_AgentRtpStatus_fields[3];
extern const pb_field_t nxp_iot_AgentRtpStatus_RtpObjectStatus_fields[4];
extern const pb_field_t nxp_iot_AgentCspStatus_fields[3];
extern const pb_field_t nxp_iot_AgentCspStatus_CspServiceStatus_fields[4];
extern const pb_field_t nxp_iot_UpdateStatusReport_fields[6];
extern const pb_field_t nxp_iot_AgentGoodbyeRequest_fields[2];
extern const pb_field_t nxp_iot_AgentCrlRequest_fields[2];
extern const pb_field_t nxp_iot_AgentCrlResponse_fields[2];

/* Maximum encoded size of messages (where known) */
#define nxp_iot_EndpointInformation_size         156
#define nxp_iot_AgentHelloRequest_size           19
#define nxp_iot_AgentHelloResponse_size          826
#define nxp_iot_AgentAdditionalData_size         6
/* nxp_iot_AgentClaimStatus_size depends on runtime parameters */
#define nxp_iot_AgentClaimStatus_DetailedClaimStatus_size 8
/* nxp_iot_AgentRtpStatus_size depends on runtime parameters */
#define nxp_iot_AgentRtpStatus_RtpObjectStatus_size 14
/* nxp_iot_AgentCspStatus_size depends on runtime parameters */
#define nxp_iot_AgentCspStatus_CspServiceStatus_size 19
/* nxp_iot_UpdateStatusReport_size depends on runtime parameters */
/* nxp_iot_AgentGoodbyeRequest_size depends on runtime parameters */
/* nxp_iot_AgentCrlRequest_size depends on runtime parameters */
#define nxp_iot_AgentCrlResponse_size            5

/* Message IDs (where set with "msgid" option) */
#ifdef PB_MSGID

#define AGENT_MESSAGES \


#endif

#ifdef __cplusplus
} /* extern "C" */
#endif
/* @@protoc_insertion_point(eof) */

#endif
