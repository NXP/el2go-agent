/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */
#ifndef _EL2GO_CSR_TLV_PARSER_H_
#define _EL2GO_CSR_TLV_PARSER_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "el2go_csr_osal_types.h"
#include "el2go_csr_integrity_verifier.h"

/* Tags used in TLV parsing for CSR generation */
#define CSR_GEN_TAG_MAGIC                   (0x40u)
#define CSR_GEN_TAG_VERSION                 (0x41u)
#define CSR_GEN_TAG_DEVICE_OPERATION        (0x42u)
#define CSR_GEN_TAG_KEY_ID                  (0x43u)
#define CSR_GEN_TAG_CSR_DEST_ADDR           (0x44u)
#define CSR_GEN_TAG_INTEGRITY_ALGORITHM     (0x47u)
#define CSR_GEN_TAG_INTEGRITY_VALUE         (0x48u)
#define CSR_GEN_TAG_ENCODING                (0x49u)

/* Tags used in TLV parsing for x.509 certificate storage */
#define CERT_STORAGE_TAG_MAGIC                   (0x40u)
#define CERT_STORAGE_TAG_VERSION                 (0x41u)
#define CERT_STORAGE_TAG_DEVICE_OPERATION        (0x42u)
#define CERT_STORAGE_TAG_KEY_ID                  (0x43u)
#define CERT_STORAGE_TAG_CERT_SRC_ADDR           (0x45u)
#define CERT_STORAGE_TAG_CERT_SRC_ADDR_SIZE      (0x46u)
#define CERT_STORAGE_TAG_INTEGRITY_ALGORITHM     (0x47u)
#define CERT_STORAGE_TAG_INTEGRITY_VALUE         (0x48u)

/* Magic values for CSR and CERT storage */
#define CSR_GEN_MAGIC_VALUE "el2gocsrgen"
#define CERT_STORAGE_MAGIC_VALUE "el2gocertstr"

/* Device operation values for CSR generation */
#define CSR_GEN_DEVICEOP_EXISTINGKEY           (0x01u)
#define CSR_GEN_DEVICEOP_NEWKEY                (0x02u)

/* Encoding values for CSR_GEN_TAG_ENCODING (optional, CSR-gen only) */
#define CSR_GEN_ENCODING_LEN                    (sizeof(uint8_t))
#define CSR_GEN_ENCODING_PEM                    (0x01u)   /* default when tag is absent */
#define CSR_GEN_ENCODING_DER                    (0x02u)
/* Any other value (including 0x00) -> kStatus_CSR_NOT_SUPPORTED */

/* Number of fields present in the CSR GEN and CERT STORAGE */
#define CSR_GEN_NUMBER_OF_TLV_FIELDS            (0x07U)
#define CERT_STORAGE_NUMBER_OF_TLV_FIELDS       (0x08U)

/* Lengths of TLV fields for certificate storage and CSR generation */
#define CSR_GEN_MAGIC_VALUE_LEN                 (sizeof(CSR_GEN_MAGIC_VALUE) - 1u) /* excluding null byte */
#define CSR_GEN_VERSION_LEN                     (sizeof(uint16_t))
#define CSR_GEN_DEVICE_OPERATION_LEN            (sizeof(uint8_t))
#define CSR_GEN_KEY_ID_LEN                      (sizeof(uint32_t))
#define CSR_GEN_CSR_DEST_ADDR_LEN               (sizeof(uint32_t))
#define CSR_GEN_INTEGRITY_ALGORITHM_LEN         (sizeof(uint32_t))
/* Total byte count of the fixed required fields (tag + length + value for each).
 * Used as a minimum sanity lower bound only; the actual CRC-covered length is
 * dynamic and reported by parse_buf_and_fill_context via integrity_covered_len. */
#define CSR_GEN_TOTAL_FIXED_FIELDS_LEN          (CSR_GEN_MAGIC_VALUE_LEN+CSR_GEN_VERSION_LEN+\
                                                CSR_GEN_DEVICE_OPERATION_LEN+CSR_GEN_KEY_ID_LEN+\
                                                CSR_GEN_CSR_DEST_ADDR_LEN+CSR_GEN_INTEGRITY_ALGORITHM_LEN+\
                                                (2u*CSR_GEN_NUMBER_OF_TLV_FIELDS)) /* tag + length fields */
                                                                                                        

#define CERT_STORAGE_MAGIC_VALUE_LEN            (sizeof(CERT_STORAGE_MAGIC_VALUE) - 1u)
#define CERT_STORAGE_VERSION_LEN                (sizeof(uint16_t))
#define CERT_STORAGE_DEVICE_OPERATION_LEN       (sizeof(uint8_t))
#define CERT_STORAGE_KEY_ID_LEN                 (sizeof(uint32_t))
#define CERT_STORAGE_CERT_SRC_ADDR_LEN          (sizeof(uint32_t))
#define CERT_STORAGE_CERT_SRC_ADDR_SIZE_LEN     (sizeof(uint32_t))
#define CERT_STORAGE_INTEGRITY_ALGORITHM_LEN    (sizeof(uint32_t))
/* See note on CSR_GEN_TOTAL_FIXED_FIELDS_LEN above - used as lower bound only. */
#define CERT_STORAGE_TOTAL_FIXED_FIELDS_LEN     (CERT_STORAGE_MAGIC_VALUE_LEN+CERT_STORAGE_VERSION_LEN+\
                                                CERT_STORAGE_DEVICE_OPERATION_LEN+CERT_STORAGE_KEY_ID_LEN+\
                                                CERT_STORAGE_CERT_SRC_ADDR_LEN+CERT_STORAGE_CERT_SRC_ADDR_SIZE_LEN+\
                                                +CERT_STORAGE_INTEGRITY_ALGORITHM_LEN+\
                                                (2u*CERT_STORAGE_NUMBER_OF_TLV_FIELDS)) 

/* Bitmask flags for REQUIRED CSR and CERT storage fields */
#define CSR_FIELD_MAGIC             (1U << 0)
#define CSR_FIELD_VERSION           (1U << 1)
#define CSR_FIELD_DEVICE_OP         (1U << 2)
#define CSR_FIELD_KEY_ID            (1U << 3)
#define CSR_FIELD_DEST_ADDR         (1U << 4)
#define CSR_FIELD_INTEGRITY_ALGO    (1U << 5)
#define CSR_FIELD_INTEGRITY_VALUE   (1U << 6)
#define CSR_ALL_REQUIRED_FIELDS     (CSR_FIELD_MAGIC | CSR_FIELD_VERSION | CSR_FIELD_DEVICE_OP | \
                                     CSR_FIELD_KEY_ID | CSR_FIELD_DEST_ADDR | \
                                     CSR_FIELD_INTEGRITY_ALGO | CSR_FIELD_INTEGRITY_VALUE)

#define CERT_FIELD_MAGIC            (1U << 0)
#define CERT_FIELD_VERSION          (1U << 1)
#define CERT_FIELD_DEVICE_OP        (1U << 2)
#define CERT_FIELD_KEY_ID           (1U << 3)
#define CERT_FIELD_SRC_ADDR         (1U << 4)
#define CERT_FIELD_SRC_ADDR_SIZE    (1U << 5)
#define CERT_FIELD_INTEGRITY_ALGO   (1U << 6)
#define CERT_FIELD_INTEGRITY_VALUE  (1U << 7)
#define CERT_ALL_REQUIRED_FIELDS    (CERT_FIELD_MAGIC | CERT_FIELD_VERSION | CERT_FIELD_DEVICE_OP | \
                                     CERT_FIELD_KEY_ID | CERT_FIELD_SRC_ADDR | CERT_FIELD_SRC_ADDR_SIZE | \
                                     CERT_FIELD_INTEGRITY_ALGO | CERT_FIELD_INTEGRITY_VALUE)                    
                                     
typedef enum _csr_parser_status
{
    kStatus_CSR_SUCCESS             = 0x5A5A5A5AU,
    kStatus_CSR_INVALID_FORMAT      = 0x33D978FFU, 
    kStatus_CSR_NOT_SUPPORTED       = 0xA8093E10U,
    kStatus_CSR_CONF_BUF_SIZE_ERR   = 0x39274EFAU,
    kStatus_CSR_TLV_FIELD_MISSING   = 0x6B1F4A82U,
} csr_parser_status_t; 

extern const size_t integrity_algo_value_size_map[NR_OF_ALGOS-1];

typedef struct __attribute__((packed)) csr_gen_context
{
    const uint8_t           *magic; 
    uint16_t                version; 
    uint8_t                 device_operation; 
    uint32_t                key_id; 
    uint32_t                destination_addr; 
    integrity_algorithms_t  integrity_algorithm; 
    const uint8_t           *integrity_value;
    uint8_t                 encoding;    /* CSR_GEN_ENCODING_PEM (default) or CSR_GEN_ENCODING_DER */
} csr_gen_context_t;
#define CSR_GEN_CONTEXT_INIT \
{ \
    .magic               = NULL, \
    .version             = 0U, \
    .device_operation    = 0U, \
    .key_id              = 0U, \
    .destination_addr    = 0U, \
    .integrity_algorithm = 0U, \
    .integrity_value     = NULL, \
    .encoding            = CSR_GEN_ENCODING_PEM \
}

typedef struct __attribute__((packed)) cert_storage_context
{
    const uint8_t           *magic; 
    uint16_t                version; 
    uint8_t                 device_operation; 
    uint32_t                key_id; 
    uint32_t                cert_source_addr;
    size_t                  cert_source_addr_size;  
    integrity_algorithms_t  integrity_algorithm; 
    const uint8_t           *integrity_value; 
} cert_storage_context_t;
#define CERT_STORAGE_CONTEXT_INIT \
{ \
    .magic                  = NULL, \
    .version                = 0U, \
    .device_operation       = 0U, \
    .key_id                 = 0U, \
    .cert_source_addr       = 0U, \
    .cert_source_addr_size  = 0U, \
    .integrity_algorithm    = 0U, \
    .integrity_value        = NULL \
}

/*! @brief Parse buffer and fill context used for CSR generation or x.509 certificate storage.
 * 
 * Parses the TLV configuration block starting at conf_buf_ptr (bounded to conf_buf_len bytes)
 * and populates either csr_gen_ctx or cert_storage_ctx depending on the magic value found.
 * Unknown or optional tags are skipped (forward-compatible BER parsing).
 * On success, *integrity_covered_len receives the number of bytes preceding the
 * INTEGRITY_VALUE TLV, i.e. the exact byte count that the CRC/integrity was computed over
 * by the Host Tool.
 * 
 * @param[in, out] csr_gen_ctx: Structure to be filled with CSR gen configuration data.
 * @param[in, out] cert_storage_ctx: Structure to be filled with x.509 cert storage configuration data. 
 * @param[in] conf_buf_ptr: Pointer to base address of the configuration block.
 * @param[in] conf_buf_len: Number of valid bytes in the configuration block (e.g. 124).
 * @param[out] integrity_covered_len: Byte count covered by the integrity value (set on SUCCESS).
 * @retval kStatus_CSR_SUCCESS Upon success.
 */
csr_parser_status_t 
parse_buf_and_fill_context(csr_gen_context_t *csr_gen_ctx,
                           cert_storage_context_t *cert_storage_ctx,
                           const uint8_t *conf_buf_ptr,
                           size_t conf_buf_len,
                           size_t *integrity_covered_len);

#ifdef __cplusplus
}
#endif

#endif /* _EL2GO_CSR_TLV_PARSER_H_ */
