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
        
        // More than 4 length bytes would exceed size_t 
        if (num_length_bytes == 0u || num_length_bytes > 4u)
        {
            return 0u; 
        }

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
 * @retval kStatus_CSR_Success Upon success.
 */
static csr_parser_status_t parse_buffer_csr(csr_gen_context_t *csr_gen_ctx, const uint8_t *conf_buf_ptr)
{
    uint8_t terminate_parsing = 0U;
    uint8_t tag    = 0U; // the tag of the current TLV
    size_t length = 0U; // the length of the current TLV
    size_t fields_present_cntr = 0U; 
    size_t offset = 0U;

    while (!terminate_parsing)  
    {
        tag = conf_buf_ptr[offset++];

        switch (tag)
        {
            case CSR_GEN_TAG_MAGIC:
                length = parse_ber_length(conf_buf_ptr, &offset);
                if (length != CSR_GEN_MAGIC_VALUE_LEN)
                {
                    return kStatus_CSR_INVALID_FORMAT;
                }
                csr_gen_ctx->magic = &conf_buf_ptr[offset];

                if (fields_present_cntr & CSR_FIELD_MAGIC)
                {
                    return kStatus_CSR_INVALID_FORMAT;
                }
                fields_present_cntr |= CSR_FIELD_MAGIC;
                break;

            case CSR_GEN_TAG_VERSION:
                length = parse_ber_length(conf_buf_ptr, &offset);
                if (length != CSR_GEN_VERSION_LEN) 
                {
                    return kStatus_CSR_INVALID_FORMAT;
                }
                csr_gen_ctx->version = get_uint16_val(&conf_buf_ptr[offset]); 

                if (fields_present_cntr & CSR_FIELD_VERSION)
                {
                    return kStatus_CSR_INVALID_FORMAT;
                }
                fields_present_cntr |= CSR_FIELD_VERSION;
                break;

            case CSR_GEN_TAG_DEVICE_OPERATION:
                length = parse_ber_length(conf_buf_ptr, &offset);
                if (length != CSR_GEN_DEVICE_OPERATION_LEN)
                {
                    return kStatus_CSR_INVALID_FORMAT;
                }
                csr_gen_ctx->device_operation = conf_buf_ptr[offset];
                
                if (fields_present_cntr & CSR_FIELD_DEVICE_OP)
                {
                    return kStatus_CSR_INVALID_FORMAT;
                }
                fields_present_cntr |= CSR_FIELD_DEVICE_OP;
                break;

            case CSR_GEN_TAG_KEY_ID:
                length = parse_ber_length(conf_buf_ptr, &offset);
                if (length != CSR_GEN_KEY_ID_LEN)
                {
                    return kStatus_CSR_INVALID_FORMAT;
                }
                csr_gen_ctx->key_id = get_uint32_val(&conf_buf_ptr[offset]); 

                if (fields_present_cntr & CSR_FIELD_KEY_ID)
                {
                    return kStatus_CSR_INVALID_FORMAT;
                }
                fields_present_cntr |= CSR_FIELD_KEY_ID;
                break;

            case CSR_GEN_TAG_CSR_DEST_ADDR:
                length = parse_ber_length(conf_buf_ptr, &offset);
                if (length != CSR_GEN_CSR_DEST_ADDR_LEN)
                {
                    return kStatus_CSR_INVALID_FORMAT;
                }
                csr_gen_ctx->destination_addr = get_uint32_val(&conf_buf_ptr[offset]); 

                if (fields_present_cntr & CSR_FIELD_DEST_ADDR)
                {
                    return kStatus_CSR_INVALID_FORMAT;
                }
                fields_present_cntr |= CSR_FIELD_DEST_ADDR;
                break;

            case CSR_GEN_TAG_INTEGRITY_ALGORTIHM:
                length = parse_ber_length(conf_buf_ptr, &offset);
                if (length != CSR_GEN_INTEGRITY_ALGORITHM_LEN)
                {
                    return kStatus_CSR_INVALID_FORMAT;
                }
                csr_gen_ctx->integrity_algorithm = (integrity_algorithms_t)(get_uint32_val(&conf_buf_ptr[offset]));
                
                if (!csr_gen_ctx->integrity_algorithm || csr_gen_ctx->integrity_algorithm >= NR_OF_ALGOS)
                {
                    return kStatus_CSR_NOT_SUPPORTED;
                }
                if (fields_present_cntr & CSR_FIELD_INTEGRITY_ALGO)
                {
                    return kStatus_CSR_INVALID_FORMAT;
                }
                fields_present_cntr |= CSR_FIELD_INTEGRITY_ALGO;
                break;

            case CSR_GEN_TAG_INTEGRITY_VALUE:         
                length = parse_ber_length(conf_buf_ptr, &offset); 
                if (length != (size_t)(integrity_algo_value_size_map[csr_gen_ctx->integrity_algorithm-1]))
                {
                    return kStatus_CSR_INVALID_FORMAT;
                }
                csr_gen_ctx->integrity_value = &conf_buf_ptr[offset];

                if (fields_present_cntr & CSR_FIELD_INTEGRITY_VALUE)
                {
                    return kStatus_CSR_INVALID_FORMAT;
                }
                fields_present_cntr |= CSR_FIELD_INTEGRITY_VALUE;
                
                // Check if all required fields are present
                if ((fields_present_cntr & CSR_ALL_REQUIRED_FIELDS) != CSR_ALL_REQUIRED_FIELDS)
                {
                    return kStatus_CSR_TLV_FIELD_MISSING;
                }

                terminate_parsing = 1U;
                break;

            default:
                return kStatus_CSR_INVALID_FORMAT;
        }
        offset += length;
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
 * @retval kStatus_CSR_Success Upon success.
 */
static csr_parser_status_t parse_buffer_cert(cert_storage_context_t *cert_storage_ctx, const uint8_t *conf_buf_ptr)
{
    uint8_t terminate_parsing = 0U;
    uint8_t tag    = 0U; // the tag of the current TLV
    size_t length = 0U; // the length of the current TLV
    size_t fields_present_cntr = 0U; 
    size_t offset = 0U;

    while (!terminate_parsing)  
    {
        tag = conf_buf_ptr[offset++];

        switch (tag)
        {
            case CERT_STORAGE_TAG_MAGIC:
                length = parse_ber_length(conf_buf_ptr, &offset);
                if (length != CERT_STORAGE_MAGIC_VALUE_LEN)
                {
                    return kStatus_CSR_INVALID_FORMAT;
                }
                cert_storage_ctx->magic = &conf_buf_ptr[offset];

                if (fields_present_cntr & CERT_FIELD_MAGIC)
                {
                    return kStatus_CSR_INVALID_FORMAT;
                }
                fields_present_cntr |= CERT_FIELD_MAGIC;
                break;

            case CERT_STORAGE_TAG_VERSION:
                length = parse_ber_length(conf_buf_ptr, &offset);
                if (length != CERT_STORAGE_VERSION_LEN)
                {
                    return kStatus_CSR_INVALID_FORMAT;
                }
                cert_storage_ctx->version = get_uint16_val(&conf_buf_ptr[offset]);

                if (fields_present_cntr & CERT_FIELD_VERSION)
                {
                    return kStatus_CSR_INVALID_FORMAT;
                }
                fields_present_cntr |= CERT_FIELD_VERSION;
                break;

            case CERT_STORAGE_TAG_DEVICE_OPERATION:
                length = parse_ber_length(conf_buf_ptr, &offset);
                if (length != CERT_STORAGE_DEVICE_OPERATION_LEN)
                {
                    return kStatus_CSR_INVALID_FORMAT;
                }
                cert_storage_ctx->device_operation = conf_buf_ptr[offset];

                if (fields_present_cntr & CERT_FIELD_DEVICE_OP)
                {
                    return kStatus_CSR_INVALID_FORMAT;
                }
                fields_present_cntr |= CERT_FIELD_DEVICE_OP;
                break;

            case CERT_STORAGE_TAG_KEY_ID:
                length = parse_ber_length(conf_buf_ptr, &offset);
                if (length != CERT_STORAGE_KEY_ID_LEN)
                {
                    return kStatus_CSR_INVALID_FORMAT;
                }
                cert_storage_ctx->key_id = get_uint32_val(&conf_buf_ptr[offset]);

                if (fields_present_cntr & CERT_FIELD_KEY_ID)
                {
                    return kStatus_CSR_INVALID_FORMAT;
                }
                fields_present_cntr |= CERT_FIELD_KEY_ID;
                break;

            case CERT_STORAGE_TAG_CERT_SRC_ADDR:
                length = parse_ber_length(conf_buf_ptr, &offset);
                if (length != CERT_STORAGE_CERT_SRC_ADDR_LEN)
                {
                    return kStatus_CSR_INVALID_FORMAT;
                }
                cert_storage_ctx->cert_source_addr = get_uint32_val(&conf_buf_ptr[offset]);

                if (fields_present_cntr & CERT_FIELD_SRC_ADDR)
                {
                    return kStatus_CSR_INVALID_FORMAT;
                }
                fields_present_cntr |= CERT_FIELD_SRC_ADDR;
                break;

            case CERT_STORAGE_TAG_CERT_SRC_ADDR_SIZE:
                length = parse_ber_length(conf_buf_ptr, &offset);
                if (length != CERT_STORAGE_CERT_SRC_ADDR_SIZE_LEN)
                {
                    return kStatus_CSR_INVALID_FORMAT;
                }
                cert_storage_ctx->cert_source_addr_size = get_uint32_val(&conf_buf_ptr[offset]);

                if (fields_present_cntr & CERT_FIELD_SRC_ADDR_SIZE)
                {
                    return kStatus_CSR_INVALID_FORMAT;
                }
                fields_present_cntr |= CERT_FIELD_SRC_ADDR_SIZE;
                break;

            case CERT_STORAGE_TAG_INTEGRITY_ALGORTIHM:
                length = parse_ber_length(conf_buf_ptr, &offset);
                if (length != CERT_STORAGE_INTEGRITY_ALGORITHM_LEN)
                {
                    return kStatus_CSR_INVALID_FORMAT;
                }
                cert_storage_ctx->integrity_algorithm = (integrity_algorithms_t)(get_uint32_val(&conf_buf_ptr[offset]));
                
                if (!cert_storage_ctx->integrity_algorithm || cert_storage_ctx->integrity_algorithm >= NR_OF_ALGOS)
                {
                    return kStatus_CSR_NOT_SUPPORTED;
                }

                if (fields_present_cntr & CERT_FIELD_INTEGRITY_ALGO)
                {
                    return kStatus_CSR_INVALID_FORMAT;
                }
                fields_present_cntr |= CERT_FIELD_INTEGRITY_ALGO;
                break;

            case CERT_STORAGE_TAG_INTEGRITY_VALUE:
                length = parse_ber_length(conf_buf_ptr, &offset);
                if (length != (size_t)(integrity_algo_value_size_map[cert_storage_ctx->integrity_algorithm-1]))
                {
                    return kStatus_CSR_INVALID_FORMAT;
                }

                cert_storage_ctx->integrity_value = &conf_buf_ptr[offset];

                if (fields_present_cntr & CERT_FIELD_INTEGRITY_VALUE)
                {
                    return kStatus_CSR_INVALID_FORMAT;
                }
                fields_present_cntr |= CERT_FIELD_INTEGRITY_VALUE;
                
                // Check if all required fields are present
                if ((fields_present_cntr & CERT_ALL_REQUIRED_FIELDS) != CERT_ALL_REQUIRED_FIELDS)
                {
                    return kStatus_CSR_TLV_FIELD_MISSING;
                }

                terminate_parsing = 1U;
                break;

            default:
                return kStatus_CSR_INVALID_FORMAT;
        }
        offset += length;
    }

    return kStatus_CSR_SUCCESS;
}

csr_parser_status_t 
parse_buf_and_fill_context(csr_gen_context_t *csr_gen_ctx, cert_storage_context_t *cert_storage_ctx, const uint8_t *conf_buf_ptr)
{
    if ( (!csr_gen_ctx && !cert_storage_ctx) || !conf_buf_ptr ) 
    {
        return kStatus_CSR_INVALID_FORMAT;
    }

    // Check the magic field in the TLV protocol, to determine which context to populate
    const char* magic_val_start = (const char*)(conf_buf_ptr+2); // skipping meta data fields

    if (!memcmp(magic_val_start, CSR_GEN_MAGIC_VALUE, CSR_GEN_MAGIC_VALUE_LEN)) // CSR generation 
    {
        return parse_buffer_csr(csr_gen_ctx, conf_buf_ptr);
    } 
    else if (!memcmp(magic_val_start, CERT_STORAGE_MAGIC_VALUE, CERT_STORAGE_MAGIC_VALUE_LEN)) // x.509 certificate storage
    {
        return parse_buffer_cert(cert_storage_ctx, conf_buf_ptr);
    }
    
    return kStatus_CSR_INVALID_FORMAT;
}