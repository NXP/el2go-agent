/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef ELS_PKC_PLATFORM_PRIV_H
#define ELS_PKC_PLATFORM_PRIV_H

#include "common/el2go_status.h"

/**
 * el2go_platform_register_el2go_key - Register the EL2GO connection auth key.
 *
 * Imports the device-specific EL2GO authentication key recipe into PSA so
 * that the S50 secure enclave can sign TLS handshake data. The key never
 * leaves the hardware.
 *
 * Two implementations exist:
 *  - els_pkc_key_registration.c   : ELS PKC (no TF-M), uses Oracle helpers.
 *  - tfm/els_pkc_key_registration_tfm.c : TF-M build, no-op (TF-M manages keys).
 *
 * The correct file is selected by CMakeLists.txt based on the build config.
 *
 * @return EL2GO_STATUS_SUCCESS on success, error code otherwise.
 */
el2go_status_t el2go_platform_register_el2go_key(void);

#endif /* ELS_PKC_PLATFORM_PRIV_H */
