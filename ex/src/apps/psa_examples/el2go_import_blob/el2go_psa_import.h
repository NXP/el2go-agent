/*
 * Copyright 2024 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

/** @file */

#ifndef _EL2GO_PSA_IMPORT_H_
#define _EL2GO_PSA_IMPORT_H_

#define BLOB_AREA       0x084B0000U
#define BLOB_AREA_SIZE  0x2000U

#include "psa/crypto_types.h"
#include "psa/crypto_values.h"
#include "psa/crypto.h"

#ifdef __ZEPHYR__
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#define LOG printf
#else
#include "fsl_debug_console.h"
#include "board.h"
#define LOG PRINTF
#endif


/**
* Parses an EL2GO blob and returns its PSA attributes and size
*
* @param[in] blob Blob data
* @param[in] blob_size Size of the blob data
* @param[out] attributes The PSA attributes specified in the blob
* @param[out] actual_blob_size The actual size of the blob

* @retval IOT_AGENT_SUCCESS upon success
* @retval IOT_AGENT_FAILURE upon failure
*/
psa_status_t iot_agent_utils_parse_blob(const uint8_t *blob, size_t blob_size, 
    psa_key_attributes_t *attributes, size_t *actual_blob_size);

/**
* Checks a specified memory area for valid blobs and imports them via PSA
*
* @param[in] blob_area Blob memory area
* @param[in] blob_size Size of the blob memory area
* @param[out] blobs_imported The number of imported blobs

* @retval IOT_AGENT_SUCCESS upon success
* @retval IOT_AGENT_FAILURE upon failure
*/
psa_status_t iot_agent_utils_psa_import_blobs_from_flash(const uint8_t *blob_area, size_t blob_area_size, 
    size_t *blobs_imported);

#ifdef __cplusplus
} // extern "C"
#endif

/*!
 *@}
 */ /* end of edgelock2go_agent_utils */

#endif /* _EL2GO_PSA_IMPORT_H_ */
