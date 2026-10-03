/*
 * Copyright 2018-2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <stddef.h>
#include <stdint.h>
#include <inttypes.h>

#include "compiler.h"
#include "debug.h"

#include "pb_decode.h"
#include "Agent.pb.h"

#include "rtp/el2go_rtp.h"

/* ========================================================================== */
/* Status description helpers (file-private)                                   */
/* ========================================================================== */

static const char *update_status_description(nxp_iot_UpdateStatusReport_UpdateStatus status)
{
    switch (status) {
    case nxp_iot_UpdateStatusReport_UpdateStatus_SUCCESS:
        return "SUCCESS";
    case nxp_iot_UpdateStatusReport_UpdateStatus_ERR_ENCODING:
        return "ERR_ENCODING";
    case nxp_iot_UpdateStatusReport_UpdateStatus_ERR_PROTOCOL:
        return "ERR_PROTOCOL";
    case nxp_iot_UpdateStatusReport_UpdateStatus_ERR_MEMORY_READ:
        return "ERR_MEMORY_READ";
    case nxp_iot_UpdateStatusReport_UpdateStatus_ERR_MEMORY_WRITE:
        return "ERR_MEMORY_WRITE";
    case nxp_iot_UpdateStatusReport_UpdateStatus_ERR_SSS_COMMUNICATION:
        return "ERR_SSS_COMMUNICATION";
    case nxp_iot_UpdateStatusReport_UpdateStatus_ERR_SSS_VERSION:
        return "ERR_SSS_VERSION";
    case nxp_iot_UpdateStatusReport_UpdateStatus_ERR_SSS_SECURE_CHANNEL:
        return "ERR_SSS_SECURE_CHANNEL";
    case nxp_iot_UpdateStatusReport_UpdateStatus_ERR_CONFIGURATION:
        return "ERR_CONFIGURATION";
    case nxp_iot_UpdateStatusReport_UpdateStatus_ERR_CONFIGURATION_TOO_MANY_DATASTORES:
        return "ERR_CONFIGURATION_TOO_MANY_DATASTORES";
    case nxp_iot_UpdateStatusReport_UpdateStatus_ERR_CONFIGURATION_TOO_MANY_KEYSTORES:
        return "ERR_CONFIGURATION_TOO_MANY_KEYSTORES";
    case nxp_iot_UpdateStatusReport_UpdateStatus_ERR_CONFIGURATION_SNI_MISSING:
        return "ERR_CONFIGURATION_SNI_MISSING";
    case nxp_iot_UpdateStatusReport_UpdateStatus_ERR_CONFIGURATION_SNI_INVALID:
        return "ERR_CONFIGURATION_SNI_INVALID";
    case nxp_iot_UpdateStatusReport_UpdateStatus_ERR_CONNECTION_QUOTA_EXCEEDED:
        return "ERR_CONNECTION_QUOTA_EXCEEDED";
    case nxp_iot_UpdateStatusReport_UpdateStatus_ERR_DEVICE_NOT_WHITELISTED:
        return "ERR_DEVICE_NOT_WHITELISTED";
    case nxp_iot_UpdateStatusReport_UpdateStatus_ERR_UPDATE_FAILED:
        return "ERR_UPDATE_FAILED";
    case nxp_iot_UpdateStatusReport_UpdateStatus_ERR_INTERNAL:
        return "ERR_INTERNAL";
    case nxp_iot_UpdateStatusReport_UpdateStatus_ERR_TIMEOUT:
        return "ERR_TIMEOUT";
    default:
        return "UNKNOWN";
    }
}

static const char *claim_status_description(nxp_iot_AgentClaimStatus_ClaimStatus status)
{
    switch (status) {
    case nxp_iot_AgentClaimStatus_ClaimStatus_SUCCESS:
        return "SUCCESS";
    case nxp_iot_AgentClaimStatus_ClaimStatus_ERR_NOT_FOUND:
        return "ERR_NOT_FOUND";
    case nxp_iot_AgentClaimStatus_ClaimStatus_ERR_WRONG_PRODUCT_TYPE:
        return "ERR_WRONG_PRODUCT_TYPE";
    case nxp_iot_AgentClaimStatus_ClaimStatus_ERR_CLAIM_CODE_REVOKED:
        return "ERR_CLAIM_CODE_REVOKED";
    case nxp_iot_AgentClaimStatus_ClaimStatus_ERR_CLAIM_CODE_LIMIT_REACHED:
        return "ERR_CLAIM_CODE_LIMIT_REACHED";
    case nxp_iot_AgentClaimStatus_ClaimStatus_ERR_CLAIM_CODE_REUSE_PROHIBITED:
        return "ERR_CLAIM_CODE_REUSE_PROHIBITED";
    case nxp_iot_AgentClaimStatus_ClaimStatus_ERR_CLAIM_CODE_READ:
        return "ERR_CLAIM_CODE_READ";
    case nxp_iot_AgentClaimStatus_ClaimStatus_ERR_CLAIM_CODE_POLICIES:
        return "ERR_CLAIM_CODE_POLICIES";
    case nxp_iot_AgentClaimStatus_ClaimStatus_ERR_CLAIM_CODE_TYPE:
        return "ERR_CLAIM_CODE_TYPE";
    case nxp_iot_AgentClaimStatus_ClaimStatus_ERR_CLAIM_CODE_FORMAT:
        return "ERR_CLAIM_CODE_FORMAT";
    case nxp_iot_AgentClaimStatus_ClaimStatus_ERR_CLAIM_CODE_DELETE:
        return "ERR_CLAIM_CODE_DELETE";
    case nxp_iot_AgentClaimStatus_ClaimStatus_ERR_CLAIM_FAILED:
        return "ERR_CLAIM_FAILED";
    case nxp_iot_AgentClaimStatus_ClaimStatus_ERR_INTERNAL:
        return "ERR_INTERNAL";
    case nxp_iot_AgentClaimStatus_ClaimStatus_ERR_TIMEOUT:
        return "ERR_TIMEOUT";
    default:
        return "UNKNOWN";
    }
}

static const char *rtp_status_description(nxp_iot_AgentRtpStatus_RtpStatus status)
{
    switch (status) {
    case nxp_iot_AgentRtpStatus_RtpStatus_SUCCESS:
        return "SUCCESS";
    case nxp_iot_AgentRtpStatus_RtpStatus_SUCCESS_NO_CHANGE:
        return "SUCCESS_NO_CHANGE";
    case nxp_iot_AgentRtpStatus_RtpStatus_ERR_RTP_FAILED:
        return "ERR_RTP_FAILED";
    case nxp_iot_AgentRtpStatus_RtpStatus_ERR_OBJECT_ATTRIBUTES_READ_FAILED:
        return "ERR_OBJECT_ATTRIBUTES_READ_FAILED";
    case nxp_iot_AgentRtpStatus_RtpStatus_ERR_OBJECT_DELETE_FAILED:
        return "ERR_OBJECT_DELETE_FAILED";
    case nxp_iot_AgentRtpStatus_RtpStatus_ERR_OBJECT_WRITE_FAILED:
        return "ERR_OBJECT_WRITE_FAILED";
    case nxp_iot_AgentRtpStatus_RtpStatus_ERR_DEFECTIVE:
        return "ERR_DEFECTIVE";
    case nxp_iot_AgentRtpStatus_RtpStatus_ERR_CURVE_INSTALLATION_FAILED:
        return "ERR_CURVE_INSTALLATION_FAILED";
    case nxp_iot_AgentRtpStatus_RtpStatus_ERR_INTERNAL:
        return "ERR_INTERNAL";
    case nxp_iot_AgentRtpStatus_RtpStatus_ERR_TIMEOUT:
        return "ERR_TIMEOUT";
    default:
        return "UNKNOWN";
    }
}

static const char *csp_status_description(nxp_iot_AgentCspStatus_CspStatus status)
{
    switch (status) {
    case nxp_iot_AgentCspStatus_CspStatus_SUCCESS:
        return "SUCCESS";
    case nxp_iot_AgentCspStatus_CspStatus_SUCCESS_NO_CHANGE:
        return "SUCCESS_NO_CHANGE";
    case nxp_iot_AgentCspStatus_CspStatus_SUCCESS_REVOKED:
        return "SUCCESS_REVOKED";
    case nxp_iot_AgentCspStatus_CspStatus_ERR_CSP_FAILED:
        return "ERR_CSP_FAILED";
    case nxp_iot_AgentCspStatus_CspStatus_ERR_KEY_SLOT_OCCUPIED:
        return "ERR_KEY_SLOT_OCCUPIED";
    case nxp_iot_AgentCspStatus_CspStatus_ERR_KEY_GENERATION_FAILED:
        return "ERR_KEY_GENERATION_FAILED";
    case nxp_iot_AgentCspStatus_CspStatus_ERR_KEY_READOUT_FAILED:
        return "ERR_KEY_READOUT_FAILED";
    case nxp_iot_AgentCspStatus_CspStatus_ERR_MEMORY_READ_FAILED:
        return "ERR_MEMORY_READ_FAILED";
    case nxp_iot_AgentCspStatus_CspStatus_ERR_MEMORY_ALLOCATION_FAILED:
        return "ERR_MEMORY_ALLOCATION_FAILED";
    case nxp_iot_AgentCspStatus_CspStatus_ERR_SERVICE_DESCRIPTOR_WRITE_FAILED:
        return "ERR_SERVICE_DESCRIPTOR_WRITE_FAILED";
    case nxp_iot_AgentCspStatus_CspStatus_ERR_MEMORY_COMMIT_FAILED:
        return "ERR_MEMORY_COMMIT_FAILED";
    case nxp_iot_AgentCspStatus_CspStatus_ERR_DEFECTIVE:
        return "ERR_DEFECTIVE";
    case nxp_iot_AgentCspStatus_CspStatus_ERR_INTERNAL:
        return "ERR_INTERNAL";
    case nxp_iot_AgentCspStatus_CspStatus_ERR_TIMEOUT:
        return "ERR_TIMEOUT";
    default:
        return "UNKNOWN";
    }
}

/* ========================================================================== */
/* Public API                                                                   */
/* ========================================================================== */

__export el2go_status_t el2go_rtp_free_status_report(void **status_report)
{
    el2go_status_t status = EL2GO_STATUS_INVALID_PARAMETER;
    nxp_iot_UpdateStatusReport *report = NULL;

    EL2GO_DBG_TRACE_API_CALL;

    if (!status_report || !*status_report)
        goto exit;

    report = (nxp_iot_UpdateStatusReport *)*status_report;
    pb_release(nxp_iot_UpdateStatusReport_fields, report);
    osal_free(report);
    *status_report = NULL;

    status = EL2GO_STATUS_SUCCESS;

exit:
    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}

__export el2go_status_t el2go_rtp_print_status_report(const void *status_report)
{
    el2go_status_t status = EL2GO_STATUS_INVALID_PARAMETER;
    const nxp_iot_UpdateStatusReport *r = NULL;
    size_t i = 0U;

    EL2GO_DBG_TRACE_API_CALL;

    if (!status_report) {
        EL2GO_PRINTF_ALWAYS("Update status report:\r\n");
        goto exit;
    }

    r = (const nxp_iot_UpdateStatusReport *)status_report;

    EL2GO_PRINTF_ALWAYS("Update status report:\r\n");

    if (r->has_status) {
        EL2GO_PRINTF_ALWAYS("  The device update %s (0x%04x: %s)\r\n",
                            (r->status == nxp_iot_UpdateStatusReport_UpdateStatus_SUCCESS ?
                                 "was successful" :
                                 "FAILED"),
                            (unsigned int)r->status, update_status_description(r->status));
    }

    if (r->has_correlationId) {
        EL2GO_PRINTF_ALWAYS("  The correlation-id for this update is %s.\r\n", r->correlationId);
    }

    if (r->has_claimStatus) {
        const nxp_iot_AgentClaimStatus *cs = &r->claimStatus;
        EL2GO_PRINTF_ALWAYS("  Status for claiming the device: 0x%04x: %s.\r\n",
                            (unsigned int)cs->status, claim_status_description(cs->status));
        for (i = 0U; i < cs->details_count; i++) {
            const nxp_iot_AgentClaimStatus_DetailedClaimStatus *d = &cs->details[i];
            EL2GO_PRINTF_ALWAYS("    Endpoint 0x%08" PRIx32 ": claim status 0x%04x: %s\n",
                                d->endpointId, (unsigned int)d->status,
                                claim_status_description(d->status));
        }
    }

    if (r->has_rtpStatus) {
        const nxp_iot_AgentRtpStatus *rs = &r->rtpStatus;
        EL2GO_PRINTF_ALWAYS("  Status for remote trust provisioning: 0x%04x: %s.\r\n",
                            (unsigned int)rs->status, rtp_status_description(rs->status));
        for (i = 0U; i < rs->details_count; i++) {
            const nxp_iot_AgentRtpStatus_RtpObjectStatus *d = &rs->details[i];
            EL2GO_PRINTF_ALWAYS("    Endpoint 0x%08" PRIx32 ", object 0x%08" PRIx32
                                ": rtp status 0x%04x: %s\n",
                                d->endpointId, d->objectId, (unsigned int)d->status,
                                rtp_status_description(d->status));
        }
    }

    if (r->has_cspStatus) {
        const nxp_iot_AgentCspStatus *cs = &r->cspStatus;
        EL2GO_PRINTF_ALWAYS("  Status for cloud service provisioning: 0x%04x: %s.\r\n",
                            (unsigned int)cs->status, csp_status_description(cs->status));
        for (i = 0U; i < cs->details_count; i++) {
            const nxp_iot_AgentCspStatus_CspServiceStatus *d = &cs->details[i];
            EL2GO_PRINTF_ALWAYS("    Endpoint 0x%08" PRIx32 ", service %" PRIu64
                                ": csp status 0x%04x: %s\n",
                                d->endpointId, (uint64_t)d->serviceId, (unsigned int)d->status,
                                csp_status_description(d->status));
        }
    }

    status = EL2GO_STATUS_SUCCESS;

exit:
    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}
