/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "pb.h"
#include "el2go_server_certificates.h"

static const PB_BYTES_ARRAY_T(EL2GO_RTP_TRUSTED_ROOT_CA_CERTIFICATES_SIZE)
    el2go_default_certs_contents = { EL2GO_RTP_TRUSTED_ROOT_CA_CERTIFICATES_SIZE,
                                     { EL2GO_RTP_TRUSTED_ROOT_CA_CERTIFICATES } };

const pb_bytes_array_t *el2go_get_default_certs(void)
{
    return (const pb_bytes_array_t *)&el2go_default_certs_contents;
}