/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */
/** @file */
#ifndef _EL2GO_CSR_CSR_PAL_UTIL_H_
#define _EL2GO_CSR_CSR_PAL_UTIL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "net_crypto.h"

/*! @brief Get the platform supported message digest algorithm for CSR generation.
 *
 * @retval Platform message digest algorithm identifier.
 */
net_crypto_md_alg_t get_msg_digest_algo(void);

#ifdef __cplusplus
}
#endif

#endif /* _EL2GO_CSR_CSR_PAL_UTIL_H_ */
