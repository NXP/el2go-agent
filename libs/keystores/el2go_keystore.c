/*
 * Copyright 2018-2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <stddef.h>
#include <stdbool.h>

#include "compiler.h"
#include "debug.h"

#include "common/el2go_keystore.h"

#include "pb.h"
#include "pb_encode.h"
#include "Dispatcher.pb.h"

#include "keystore_priv.h"

__export __weak el2go_status_t el2go_keystore_init(uint32_t id, el2go_platform_ctx_t *platform_ctx,
                                                   el2go_keystore_t *keystore)
{
    (void)id;
    (void)platform_ctx;

    if (!keystore) {
        return EL2GO_STATUS_INVALID_PARAMETER;
    }

    return EL2GO_STATUS_SUCCESS;
}

__export __weak el2go_status_t el2go_keystore_free(el2go_keystore_t *keystore)
{
    if (!keystore) {
        return EL2GO_STATUS_INVALID_PARAMETER;
    }

    keystore->platform_ctx = NULL;

    return EL2GO_STATUS_SUCCESS;
}

__export __weak el2go_status_t el2go_keystore_open_session(el2go_keystore_t *keystore)
{
    if (!keystore) {
        return EL2GO_STATUS_INVALID_PARAMETER;
    }

    return EL2GO_STATUS_SUCCESS;
}

__export __weak el2go_status_t el2go_keystore_close_session(el2go_keystore_t *keystore)
{
    if (!keystore) {
        return EL2GO_STATUS_INVALID_PARAMETER;
    }

    return EL2GO_STATUS_SUCCESS;
}

__weak el2go_status_t el2go_keystore_handle_request(void *ctx, const pb_field_t *message_type,
                                                    pb_istream_t *istream, pb_ostream_t *ostream)
{
    (void)ctx;
    (void)message_type;
    (void)istream;
    (void)ostream;

    return EL2GO_STATUS_RTP_DECODE_ERROR;
}

__weak el2go_status_t el2go_keystore_get_cert_from_srv_desc(
    el2go_keystore_t *keystore, const nxp_iot_ServiceDescriptor *service_descriptor,
    const uint8_t **client_cert, size_t *client_cert_len)
{
    (void)keystore;
    (void)service_descriptor;
    (void)client_cert;
    (void)client_cert_len;

    EL2GO_DBG_PRINTF(ERROR, "el2go_keystore_get_cert_from_srv_desc not implemented "
                            "for this keystore type\n");
    return EL2GO_STATUS_UNSUPPORTED_OPERATION;
}

__weak nxp_iot_EndpointType el2go_keystore_get_endpoint_type(const el2go_keystore_t *keystore)
{
    if (!keystore)
        return nxp_iot_EndpointType_INVALID;

    switch (keystore->type) {
    case EL2GO_KEYSTORE_PSA:
        return nxp_iot_EndpointType_KS_PSA;
    case EL2GO_KEYSTORE_SSS:
        return nxp_iot_EndpointType_KS_SSS_SE05X;
    default:
        return nxp_iot_EndpointType_INVALID;
    }
}

__weak el2go_status_t el2go_keystore_import_claimcode(el2go_keystore_t *keystore,
                                                      const char *claimcode, size_t claimcode_len)
{
    (void)keystore;
    (void)claimcode;
    (void)claimcode_len;

    /* default no-op: keystores that do not need claim injection succeed silently */
    return EL2GO_STATUS_SUCCESS;
}

__export __weak el2go_status_t el2go_keystore_import_claimcode_from_flash(el2go_keystore_t *keystore)
{
    (void)keystore;
    /* default no-op: platforms without flash claimcode injection succeed silently */
    return EL2GO_STATUS_SUCCESS;
}

__weak el2go_status_t el2go_keystore_get_endpoint_info(void *ctx, nxp_iot_EndpointInformation *info)
{
    (void)ctx;
    /* type and endpointId are pre-filled by the dispatcher build step */
    info->has_type = true;
    info->has_endpointId = true;

    return EL2GO_STATUS_SUCCESS;
}

__export __weak el2go_status_t el2go_keystore_import_claimcode(el2go_keystore_t *keystore,
                                                               const char *claimcode,
                                                               size_t claimcode_len)
{
    (void)keystore;
    (void)claimcode;
    (void)claimcode_len;

    /* not mandatory for all keystore implementations */
    return EL2GO_STATUS_SUCCESS;
}