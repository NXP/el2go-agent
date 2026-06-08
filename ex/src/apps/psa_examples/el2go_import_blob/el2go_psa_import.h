/*
 * Copyright 2024, 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

/** @file */

#ifndef _EL2GO_PSA_IMPORT_H_
#define _EL2GO_PSA_IMPORT_H_

#ifndef BLOB_AREA 
#define BLOB_AREA       0x084B0000U
#endif

#ifndef BLOB_AREA_SIZE
#define BLOB_AREA_SIZE  0x2000U
#endif

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
 * Checks a specified memory area for valid blobs and imports them via PSA.
 * Additionally exports the PSA key IDs of all successfully imported blobs into a caller-provided array.
 *
 * @param[in]  blob_area           Blob memory area
 * @param[in]  blob_area_size      Size of the blob memory area
 * @param[out] blobs_imported      The number of imported blobs (also the number of valid entries in psa_key_id_list)
 * @param[out] psa_key_id_list     Array to be filled with PSA key IDs of imported blobs, or NULL if not needed
 * @param[in]  psa_key_id_list_len Maximum number of entries psa_key_id_list can hold
 *
 * @retval PSA_SUCCESS upon success
 * @retval PSA_ERROR_GENERIC_ERROR upon failure
 * @retval PSA_ERROR_BUFFER_TOO_SMALL if psa_key_id_list is too small to hold all imported key IDs
 */
psa_status_t iot_agent_utils_psa_import_blobs_from_flash_exp_key_id(const uint8_t *blob_area,
    size_t blob_area_size, size_t *blobs_imported, psa_key_id_t *psa_key_id_list, size_t psa_key_id_list_len);

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
