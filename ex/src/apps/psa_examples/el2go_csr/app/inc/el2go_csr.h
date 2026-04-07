/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef _EL2GO_CSR_H_
#define _EL2GO_CSR_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "el2go_csr_platform.h"
#include "integrity_verifier.h"
#include "csr_util.h"
#include "el2go_csr_tlv_parser.h"
#include "el2go_csr_memory.h"
#include "el2go_csr_console.h"
#include "el2go_csr_psa_key.h"

#define MAX_X509_CERT_SIZE (4096U)
#define MAX_CSR_SIZE (2048U)
#define SPSDK_STATUS_CODE_SUCCESS (0x3BBBA12DU)

#ifdef __cplusplus
}
#endif

#endif /* _EL2GO_CSR_H_ */