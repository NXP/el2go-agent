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

#include <stddef.h>
#include <stdint.h>
#include <string.h>
  
// Tags used in TLV parsing for CSR generation 
#define CSR_GEN_TAG_MAGIC                   (0x40u)
#define CSR_GEN_TAG_VERSION                 (0x41u)
#define CSR_GEN_TAG_DEVICE_OPERATION        (0x42u)
#define CSR_GEN_TAG_KEY_ID                  (0x43u)
#define CSR_GEN_TAG_CSR_DEST_ADDR           (0x44u)
#define CSR_GEN_TAG_INTEGRITY_ALGORTIHM     (0x45u)
#define CSR_GEN_TAG_INTEGRITY_VALUE         (0x46u)

// Tags used in TLV parsing for x.509 certificate storage
#define CERT_STORAGE_TAG_MAGIC                   (0x50u)
#define CERT_STORAGE_TAG_VERSION                 (0x51u)
#define CERT_STORAGE_TAG_DEVICE_OPERATION        (0x52u)
#define CERT_STORAGE_TAG_KEY_ID                  (0x53u)
#define CERT_STORAGE_TAG_CERT_SRC_ADDR           (0x54u)
#define CERT_STORAGE_TAG_CERT_SRC_ADDR_SIZE      (0x55u)
#define CERT_STORAGE_TAG_INTEGRITY_ALGORTIHM     (0x56u)
#define CERT_STORAGE_TAG_INTEGRITY_VALUE         (0x57u)

// Magic values for CSR and CERT storage
#define CSR_GEN_MAGIC_VALUE "el2gocsrgen"
#define CERT_STORAGE_MAGIC_VALUE "el2gocertstr"

// Lengths of TLV fields for certificate storage and CSR genration
#define CSR_GEN_MAGIC_VALUE_LEN                 (sizeof(CSR_GEN_MAGIC_VALUE) - 1u)
#define CSR_GEN_VERSION_LEN                     (sizeof(uint16_t))
#define CSR_GEN_DEVICE_OPERATION_LEN            (sizeof(uint8_t))
#define CSR_GEN_KEY_ID_LEN                      (sizeof(uint32_t))
#define CSR_GEN_CSR_DEST_ADDR_LEN               (sizeof(uint32_t))
#define CSR_GEN_INTEGRITY_ALGORITHM_LEN         (sizeof(uint32_t))

#define CERT_STORAGE_MAGIC_VALUE_LEN            (sizeof(CERT_STORAGE_MAGIC_VALUE) - 1u)
#define CERT_STORAGE_VERSION_LEN                (sizeof(uint16_t))
#define CERT_STORAGE_DEVICE_OPERATION_LEN       (sizeof(uint8_t))
#define CERT_STORAGE_KEY_ID_LEN                 (sizeof(uint32_t))
#define CERT_STORAGE_CERT_SRC_ADDR_LEN          (sizeof(uint32_t))
#define CERT_STORAGE_CERT_SRC_ADDR_SIZE_LEN     (sizeof(uint32_t))
#define CERT_STORAGE_INTEGRITY_ALGORITHM_LEN    (sizeof(uint32_t))

typedef enum _csr_parser_status
{
    kStatus_CSR_SUCCESS             = 0x5A5A5A5A,
    kStatus_CSR_INVALID_PARAM       = 0x78D87C72,
    kStatus_CSR_INVALID_FORMAT      = 0x33D978FF, 
    kStatus_CSR_NOT_SUPPORTED       = 0xA8093E10,
    kStatus_CSR_CONF_BUF_SIZE_ERR   = 0x39274EFA,
} csr_parser_status_t; 

typedef enum _integrity_algorithms
{
    CRC_32 = 0x1,
    // Add here further algo's if needed. 
    // e.g. HMAC_SHA256 = 0x2, <-- count chronologically up!
    
    NR_OF_ALGOS // DO NOT insert any new entry below this line!
} integrity_algorithms_t;

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
} csr_gen_context_t;

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

/*! @brief Parse buffer and fill context used for CSR generation or x.509 certificate storage.
 * 
 * This function is parsing buffer to spot EL2GO configuration block and fills up the configuration 
 * block context used for CSR generation or x.509 certificate storage. Depending on the magic value 
 * in the buffer, either csr_gen_ctx or cert_storage_ctx will be populated accordingly.
 * 
 * @param[in, out] csr_gen_ctx: Structure to be filled with parsed with CSR gen configuration data.
 * @param[in, out] cert_storage_ctx: Structure to be filled with parsed x.509 cert storage configuration data. 
 * @param[in] conf_buf_ptr: Pointer base address of the configuration block.
 * @param[in] conf_buf_ptr_size: Size of the configuration block in bytes.
 * @retval kStatus_CSR_Success Upon success.
 */
csr_parser_status_t 
parse_buf_and_fill_context(csr_gen_context_t *csr_gen_ctx, cert_storage_context_t *cert_storage_ctx, 
    const uint8_t *conf_buf_ptr, size_t conf_buf_ptr_size);

#ifdef __cplusplus
}
#endif

#endif /* _EL2GO_CSR_TLV_PARSER_H_ */
