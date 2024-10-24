/*
 * Copyright 2022-2024 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */
#ifndef _IOT_AGENT_CLAIMCODE_ENCRYPT_H_
#define _IOT_AGENT_CLAIMCODE_ENCRYPT_H_

#include "nxp_iot_agent_status.h"
#include "stdint.h"
#include "stddef.h"

#if NXP_IOT_AGENT_HAVE_PSA
#if !NXP_IOT_AGENT_HAVE_PSA_IMPL_SMW

#ifdef __cplusplus
extern "C" {
#endif

/*! @defgroup edgelock2go_agent_claimcode_encrypt Device-specifically encrypt a claimcode 
 * for EdgeLock 2GO.
*
* @ingroup edgelock2go_agent_claimcode_encrypt
*
* @brief Provides functionality to encrypt claimcode and store as binary object in trusted storage.
*
*/

/*!
* @addtogroup edgelock2go_agent_claimcode_encrypt
* @{
*/

/**
 * @brief Encrypt a claimcode.
 */
iot_agent_status_t iot_agent_claimcode_encrypt(const char * claimcode,
        const uint8_t* el2go_public_key, size_t el2go_public_key_size, 
        uint8_t* claimcode_blob, size_t* claimcode_blob_size);

/**
 * @brief Encrypt a claimcode and put into trusted storage.
 * @param[in] claimcode: Pointer to null-terminated string containing claimcode.
 * @return Success if storage of new claimcode is successful.
 */
iot_agent_status_t iot_agent_claimcode_encrypt_and_import(char *claimcode, 
        const uint8_t* el2go_public_key, size_t el2go_public_key_size);


#ifdef __cplusplus
} // extern "C"
#endif

/*!
*@}
*/ /* end of edgelock2go_agent_claimcode_encrypt */

#endif // !NXP_IOT_AGENT_HAVE_PSA_IMPL_SMW
#endif // NXP_IOT_AGENT_HAVE_PSA

#endif // #ifndef _IOT_AGENT_CLAIMCODE_ENCRYPT_H_
