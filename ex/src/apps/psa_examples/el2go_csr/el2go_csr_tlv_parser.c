/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "el2go_csr_tlv_parser.h"

const size_t integrity_algo_value_size_map[NR_OF_ALGOS-1] = {
    4U // CRC_32 produces 4 bytes
};

/** @brief Gets the 16-bit value from the value buffer.
 *
 */
static uint16_t get_uint16_val(const uint8_t *input)
{
    uint16_t output = 0U;
    output = *input;
    output <<= 8;
    output |= *(input + 1);
    return output;
}

/** @brief Gets the 32-bit value from the value buffer.
 *
 */
static uint32_t get_uint32_val(const uint8_t *input)
{
    uint32_t output = 0U;

    for (int i = 0; i < 4; i++)
    {
        output = (output << 8) | input[i];
    }
    return output;
}

/*! @brief Extract number of bytes from BER encoded length field.
 *
 * This function is used to extract the length field from a BER-encoded TLV structure.
 * 
 * @param[in] buf: Pointer to buffer containing BER-encoded length field.
 * @param[in] offset: Pointer to current offset in buffer, will be updated after parsing.
 * @retval Returns the extracted length value from the BER-encoded length field.
 */
static size_t parse_ber_length(const uint8_t *buf, size_t *offset)
{
    size_t length = 0u;
    uint8_t first_byte = 0u; 
    
    if (!buf || !offset)
    {
        return 0u;
    }

    first_byte = (size_t)buf[(*offset)++];
    
    if ((first_byte & 0x80u) == 0u)
    {
        // Short form: length is 0-127
        length = first_byte;
    }
    else
    {
        // Long form: bits 0-6 indicate number of subsequent length bytes
        uint8_t num_length_bytes = first_byte & 0x7Fu;
        
        for (uint8_t i = 0u; i < num_length_bytes; i++)
        {
            length = (length << 8) | (size_t)buf[(*offset)++];
        }
    }

    return length;
}

/*! @brief Parse buffer to spot EL2GO config block used for CSR generation.
 *
 * This internal function is parsing buffer and fills up a the the configuration 
 * block context used for CSR generation.
 * 
 * @param[in, out] csr_gen_ctx: Structure to be filled with parsed configuration data.
 * @param[in] conf_buf_ptr: Pointer base address of the configuration block.
 * @param[in] conf_buf_ptr_size: Size of the configuration block buffer.
 * @retval kStatus_CSR_Success Upon success.
 */
static csr_parser_status_t parse_buffer_csr(csr_gen_context_t *csr_gen_ctx, 
    const uint8_t *conf_buf_ptr, size_t conf_buf_ptr_size)
{
    uint8_t tag = 0u;
    uint8_t nr_tlv_fields = 0u; 
    size_t  offset = 0u;
    size_t  length = 0u;

    if (!csr_gen_ctx || !conf_buf_ptr)
    {
        return kStatus_CSR_INVALID_PARAM;
    }

    nr_tlv_fields = 1 + (CSR_GEN_TAG_INTEGRITY_VALUE - CSR_GEN_TAG_MAGIC);

    // Validate buffer size is sufficient for parsing
    if (conf_buf_ptr_size )
    for (uint8_t i = 0u; i < nr_tlv_fields; i++)
    {
        uint8_t current_tag = i + CSR_GEN_TAG_MAGIC;

        tag = conf_buf_ptr[offset++];
        
        if (tag != current_tag)
        {
            return kStatus_CSR_INVALID_FORMAT;
        }
        
        length = parse_ber_length(conf_buf_ptr, &offset);

        switch (tag)
        {
            case CSR_GEN_TAG_MAGIC:
                if (length != CSR_GEN_MAGIC_VALUE_LEN)
                {
                    return kStatus_CSR_INVALID_FORMAT;
                }
                csr_gen_ctx->magic = &conf_buf_ptr[offset];
                break;

            case CSR_GEN_TAG_VERSION:
                if (length != CSR_GEN_VERSION_LEN) 
                {
                    return kStatus_CSR_INVALID_FORMAT;
                }
                csr_gen_ctx->version = get_uint16_val(&conf_buf_ptr[offset]); 
                break;

            case CSR_GEN_TAG_DEVICE_OPERATION:
                if (length != CSR_GEN_DEVICE_OPERATION_LEN)
                {
                    return kStatus_CSR_INVALID_FORMAT;
                }
                csr_gen_ctx->device_operation = conf_buf_ptr[offset];
                break;

            case CSR_GEN_TAG_KEY_ID:
                if (length != CSR_GEN_KEY_ID_LEN)
                {
                    return kStatus_CSR_INVALID_FORMAT;
                }
                csr_gen_ctx->key_id = get_uint32_val(&conf_buf_ptr[offset]); 
                break;

            case CSR_GEN_TAG_CSR_DEST_ADDR:
                if (length != CSR_GEN_CSR_DEST_ADDR_LEN)
                {
                    return kStatus_CSR_INVALID_FORMAT;
                }
                csr_gen_ctx->destination_addr = get_uint32_val(&conf_buf_ptr[offset]); 
                break;

            case CSR_GEN_TAG_INTEGRITY_ALGORTIHM:
                if (length != CSR_GEN_INTEGRITY_ALGORITHM_LEN)
                {
                    return kStatus_CSR_INVALID_FORMAT;
                }
                csr_gen_ctx->integrity_algorithm = (integrity_algorithms_t)(get_uint32_val(&conf_buf_ptr[offset]));
                
                if (!csr_gen_ctx->integrity_algorithm || csr_gen_ctx->integrity_algorithm >= NR_OF_ALGOS)
                {
                    return kStatus_CSR_NOT_SUPPORTED;
                }
                break;

            case CSR_GEN_TAG_INTEGRITY_VALUE:
                csr_gen_ctx->integrity_value = &conf_buf_ptr[offset];
                break;

            default:
                return kStatus_CSR_INVALID_FORMAT;
        }

        offset += length;
        if (offset > conf_buf_ptr_size)
        {
            return kStatus_CSR_CONF_BUF_SIZE_ERR;
        }
    }

    return kStatus_CSR_SUCCESS;
}

/*! @brief Parse buffer to spot EL2GO config block used for x.509 certificate storage.
 *
 * This internal function is parsing buffer and fills up a the the configuration 
 * block context used for x.509 certificate storage. 
 * 
 * @param[in, out] cert_storage_ctx: Structure to be filled with parsed configuration data.
 * @param[in] conf_buf_ptr: Pointer base address of the configuration block.
 * @param[in] conf_buf_ptr_size: Size of the configuration block buffer.
 * @retval kStatus_CSR_Success Upon success.
 */
static csr_parser_status_t parse_buffer_cert(cert_storage_context_t *cert_storage_ctx, 
    const uint8_t *conf_buf_ptr, size_t conf_buf_ptr_size)
{
    uint8_t tag = 0u;
    uint8_t nr_tlv_fields = 0u; 
    size_t  offset = 0u;
    size_t  length = 0u;

    if (!cert_storage_ctx || !conf_buf_ptr)
    {
        return kStatus_CSR_INVALID_PARAM;
    }

    nr_tlv_fields = 1 + (CERT_STORAGE_TAG_INTEGRITY_VALUE - CERT_STORAGE_TAG_MAGIC);

    for (uint8_t i = 0u; i < nr_tlv_fields; i++)
    {
        uint8_t current_tag = i + CERT_STORAGE_TAG_MAGIC;

        tag = conf_buf_ptr[offset++];
        
        if (tag != current_tag)
        {
            return kStatus_CSR_INVALID_FORMAT;
        }

        length = parse_ber_length(conf_buf_ptr, &offset);

        switch (tag)
        {
            case CERT_STORAGE_TAG_MAGIC:
                if (length != CERT_STORAGE_MAGIC_VALUE_LEN) 
                {
                    return kStatus_CSR_INVALID_FORMAT;
                }
                cert_storage_ctx->magic = &conf_buf_ptr[offset];
                break;

            case CERT_STORAGE_TAG_VERSION:
                if (length != CERT_STORAGE_VERSION_LEN)
                {
                    return kStatus_CSR_INVALID_FORMAT;
                }
                cert_storage_ctx->version = get_uint16_val(&conf_buf_ptr[offset]); 
                break;

            case CERT_STORAGE_TAG_DEVICE_OPERATION:
                if (length != CERT_STORAGE_DEVICE_OPERATION_LEN)
                {
                    return kStatus_CSR_INVALID_FORMAT;
                }
                cert_storage_ctx->device_operation = conf_buf_ptr[offset];
                break;

            case CERT_STORAGE_TAG_KEY_ID:
                if (length != CERT_STORAGE_KEY_ID_LEN)
                {
                    return kStatus_CSR_INVALID_FORMAT;
                }
                cert_storage_ctx->key_id = get_uint32_val(&conf_buf_ptr[offset]); 
                break;

            case CERT_STORAGE_TAG_CERT_SRC_ADDR:
                if (length != CERT_STORAGE_CERT_SRC_ADDR_LEN)
                {
                    return kStatus_CSR_INVALID_FORMAT;
                }
                cert_storage_ctx->cert_source_addr = get_uint32_val(&conf_buf_ptr[offset]); 
                break;

            case CERT_STORAGE_TAG_CERT_SRC_ADDR_SIZE:
                if (length != CERT_STORAGE_CERT_SRC_ADDR_SIZE_LEN)
                {
                    return kStatus_CSR_INVALID_FORMAT;
                }
                cert_storage_ctx->cert_source_addr_size = get_uint32_val(&conf_buf_ptr[offset]); 
                break;

            case CERT_STORAGE_TAG_INTEGRITY_ALGORTIHM:
                if (length != CERT_STORAGE_INTEGRITY_ALGORITHM_LEN)
                {
                    return kStatus_CSR_INVALID_FORMAT;
                }
                cert_storage_ctx->integrity_algorithm = (integrity_algorithms_t)(get_uint32_val(&conf_buf_ptr[offset]));
                
                if (!cert_storage_ctx->integrity_algorithm || cert_storage_ctx->integrity_algorithm >= NR_OF_ALGOS)
                {
                    return kStatus_CSR_NOT_SUPPORTED;
                }
                break;

            case CERT_STORAGE_TAG_INTEGRITY_VALUE:
                cert_storage_ctx->integrity_value = &conf_buf_ptr[offset];
                break;

            default:
                return kStatus_CSR_INVALID_FORMAT;
        }

        offset += length;
        if (offset > conf_buf_ptr_size)
        {
            return kStatus_CSR_CONF_BUF_SIZE_ERR;
        }
    }

    return kStatus_CSR_SUCCESS;
}

csr_parser_status_t parse_buf_and_fill_context(csr_gen_context_t *csr_gen_ctx, 
    cert_storage_context_t *cert_storage_ctx, const uint8_t *conf_buf_ptr, size_t conf_buf_ptr_size)
{
    if ( (!csr_gen_ctx && !cert_storage_ctx) || !conf_buf_ptr ) 
    {
        return kStatus_CSR_INVALID_PARAM;
    }

    // Check the magic field in the TLV protocol, to determine which context to populate
    const char* magic_val_start = (const char*)(conf_buf_ptr+2); // skipping meta data fields

    if (!memcmp(magic_val_start, CSR_GEN_MAGIC_VALUE, CSR_GEN_MAGIC_VALUE_LEN)) // CSR generation 
    {
        return parse_buffer_csr(csr_gen_ctx, conf_buf_ptr, conf_buf_ptr_size);
    } 
    else if (!memcmp(magic_val_start, CERT_STORAGE_MAGIC_VALUE, CERT_STORAGE_MAGIC_VALUE_LEN)) // x.509 certificate storage
    {
        return parse_buffer_cert(cert_storage_ctx, conf_buf_ptr, conf_buf_ptr_size);
    }
    
    return kStatus_CSR_INVALID_FORMAT;
}