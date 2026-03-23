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

/** @brief  Parses TLV length field according to BER encoding rules.
 *          Note: Taken from mbedTLS
 * 
 */
static csr_parser_status_t get_len(const unsigned char **p, const unsigned char *end, size_t *len)
{
    if ((end - *p) < 1)
    {
        return (kStatus_CSR_INVALID_PARAM);
    }

    if ((**p & 0x80u) == 0u)
    {
        *len = *(*p)++;
    }
    else
    {
        switch (**p & 0x7Fu)
        {
            case 1:
                if ((end - *p) < 2)
                {
                    return (kStatus_CSR_INVALID_PARAM);
                }

                *len = (*p)[1];
                (*p) += 2;
                break;

            case 2:
                if ((end - *p) < 3)
                {
                    return (kStatus_CSR_INVALID_PARAM);
                }

                *len = ((size_t)(*p)[1] << 8) | (*p)[2];
                (*p) += 3;
                break;

            case 3:
                if ((end - *p) < 4)
                {
                    return (kStatus_CSR_INVALID_PARAM);
                }

                *len = ((size_t)(*p)[1] << 16) | ((size_t)(*p)[2] << 8) | (*p)[3];
                (*p) += 4;
                break;

            case 4:
                if ((end - *p) < 5)
                {
                    return (kStatus_CSR_INVALID_PARAM);
                }

                *len = ((size_t)(*p)[1] << 24) | ((size_t)(*p)[2] << 16) | ((size_t)(*p)[3] << 8) | (*p)[4];
                (*p) += 5;
                break;

            default:
                return (kStatus_CSR_INVALID_PARAM);
        }
    }
    if (*len > (size_t)(end - *p))
    {
        return (kStatus_CSR_INVALID_PARAM);
    }
    return (kStatus_CSR_SUCCESS);
}

/**
 * @brief   Parse TLV encoded buffer and fill CSR generation and certificate storage contexts.
 *          Note: Taken from mbedTLS
 * 
 */
static csr_parser_status_t get_tag(const unsigned char **p, const unsigned char *end, size_t *len, uint8_t tag)
{
    if ((end - *p) < 1)
    {
        return (kStatus_CSR_INVALID_PARAM);
    }

    if (**p != tag)
    {
        return (kStatus_CSR_INVALID_PARAM);
    }

    (*p)++;

    return (get_len(p, end, len));
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
    csr_parser_status_t status = kStatus_CSR_INVALID_FORMAT;
    uint8_t tag    = 0U; // the tag of the current TLV
    size_t length = 0U; // the length of the current TLV
    const uint8_t *cmd_ptr = conf_buf_ptr;
    const uint8_t *end     = cmd_ptr + conf_buf_ptr_size;
    size_t fields_present_cntr = 0; 

    while ((cmd_ptr + 1) < end)
    {
        tag        = *cmd_ptr;
        status = get_tag(&cmd_ptr, end, &length, tag);

        if (status != kStatus_CSR_SUCCESS)
        {
            return status; 
        }

        switch (tag)
        {
            case CSR_GEN_TAG_MAGIC:
                if (length != CSR_GEN_MAGIC_VALUE_LEN)
                {
                    return kStatus_CSR_INVALID_FORMAT;
                }
                csr_gen_ctx->magic = cmd_ptr;
                fields_present_cntr |= CSR_FIELD_MAGIC;
                break;

            case CSR_GEN_TAG_VERSION:
                if (length != CSR_GEN_VERSION_LEN) 
                {
                    return kStatus_CSR_INVALID_FORMAT;
                }
                csr_gen_ctx->version = get_uint16_val(cmd_ptr); 
                fields_present_cntr |= CSR_FIELD_VERSION;
                break;

            case CSR_GEN_TAG_DEVICE_OPERATION:
                if (length != CSR_GEN_DEVICE_OPERATION_LEN)
                {
                    return kStatus_CSR_INVALID_FORMAT;
                }
                csr_gen_ctx->device_operation = *cmd_ptr;
                fields_present_cntr |= CERT_FIELD_DEVICE_OP;
                break;

            case CSR_GEN_TAG_KEY_ID:
                if (length != CSR_GEN_KEY_ID_LEN)
                {
                    return kStatus_CSR_INVALID_FORMAT;
                }
                csr_gen_ctx->key_id = get_uint32_val(cmd_ptr); 
                fields_present_cntr |= CSR_FIELD_KEY_ID;
                break;

            case CSR_GEN_TAG_CSR_DEST_ADDR:
                if (length != CSR_GEN_CSR_DEST_ADDR_LEN)
                {
                    return kStatus_CSR_INVALID_FORMAT;
                }
                csr_gen_ctx->destination_addr = get_uint32_val(cmd_ptr); 
                fields_present_cntr |= CSR_FIELD_DEST_ADDR;
                break;

            case CSR_GEN_TAG_INTEGRITY_ALGORTIHM:
                if (length != CSR_GEN_INTEGRITY_ALGORITHM_LEN)
                {
                    return kStatus_CSR_INVALID_FORMAT;
                }
                csr_gen_ctx->integrity_algorithm = (integrity_algorithms_t)(get_uint32_val(cmd_ptr));
                
                if (!csr_gen_ctx->integrity_algorithm || csr_gen_ctx->integrity_algorithm >= NR_OF_ALGOS)
                {
                    return kStatus_CSR_NOT_SUPPORTED;
                }
                fields_present_cntr |= CSR_FIELD_INTEGRITY_ALGO;
                break;

            case CSR_GEN_TAG_INTEGRITY_VALUE:
                csr_gen_ctx->integrity_value = cmd_ptr;
                fields_present_cntr |= CSR_FIELD_INTEGRITY_VALUE;
                break;

            default:
                return kStatus_CSR_INVALID_FORMAT;
        }
        cmd_ptr += length;
    }

    // Check if all required fields are present
    if ((fields_present_cntr & CSR_ALL_REQUIRED_FIELDS) != CSR_ALL_REQUIRED_FIELDS)
    {
        return kStatus_CSR_TLV_FIELD_MISSING;
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
    csr_parser_status_t status = kStatus_CSR_INVALID_FORMAT;
    uint8_t tag    = 0U; // the tag of the current TLV
    size_t length = 0U; // the length of the current TLV
    const uint8_t *cmd_ptr = conf_buf_ptr;
    const uint8_t *end     = conf_buf_ptr + conf_buf_ptr_size;
    size_t fields_present_cntr = 0; 

    while ((cmd_ptr + 1) < end)
    {
        tag        = *cmd_ptr;
        status = get_tag(&cmd_ptr, end, &length, tag);

        if (status != kStatus_CSR_SUCCESS)
        {
            return status;
        }
        switch (tag)
        {
            case CERT_STORAGE_TAG_MAGIC:
                if (length != CERT_STORAGE_MAGIC_VALUE_LEN) 
                {
                    return kStatus_CSR_INVALID_FORMAT;
                }
                fields_present_cntr |= CERT_FIELD_MAGIC;
                cert_storage_ctx->magic = cmd_ptr;
                break;

            case CERT_STORAGE_TAG_VERSION:
                if (length != CERT_STORAGE_VERSION_LEN)
                {
                    return kStatus_CSR_INVALID_FORMAT;
                }
                cert_storage_ctx->version = get_uint16_val(cmd_ptr);
                fields_present_cntr |= CERT_FIELD_VERSION;
                break;

            case CERT_STORAGE_TAG_DEVICE_OPERATION:
                if (length != CERT_STORAGE_DEVICE_OPERATION_LEN)
                {
                    return kStatus_CSR_INVALID_FORMAT;
                }
                cert_storage_ctx->device_operation = *cmd_ptr;
                fields_present_cntr |= CERT_FIELD_DEVICE_OP;
                break;

            case CERT_STORAGE_TAG_KEY_ID:
                if (length != CERT_STORAGE_KEY_ID_LEN)
                {
                    return kStatus_CSR_INVALID_FORMAT;
                }
                cert_storage_ctx->key_id = get_uint32_val(cmd_ptr); 
                fields_present_cntr |= CERT_FIELD_KEY_ID;
                break;

            case CERT_STORAGE_TAG_CERT_SRC_ADDR:
                if (length != CERT_STORAGE_CERT_SRC_ADDR_LEN)
                {
                    return kStatus_CSR_INVALID_FORMAT;
                }
                cert_storage_ctx->cert_source_addr = get_uint32_val(cmd_ptr); 
                fields_present_cntr |= CERT_FIELD_SRC_ADDR;
                break;

            case CERT_STORAGE_TAG_CERT_SRC_ADDR_SIZE:
                if (length != CERT_STORAGE_CERT_SRC_ADDR_SIZE_LEN)
                {
                    return kStatus_CSR_INVALID_FORMAT;
                }
                cert_storage_ctx->cert_source_addr_size = get_uint32_val(cmd_ptr); 
                fields_present_cntr |= CERT_FIELD_SRC_ADDR_SIZE;
                break;

            case CERT_STORAGE_TAG_INTEGRITY_ALGORTIHM:
                if (length != CERT_STORAGE_INTEGRITY_ALGORITHM_LEN)
                {
                    return kStatus_CSR_INVALID_FORMAT;
                }
                cert_storage_ctx->integrity_algorithm = (integrity_algorithms_t)(get_uint32_val(cmd_ptr));
                
                if (!cert_storage_ctx->integrity_algorithm || cert_storage_ctx->integrity_algorithm >= NR_OF_ALGOS)
                {
                    return kStatus_CSR_NOT_SUPPORTED;
                }
                fields_present_cntr |= CERT_FIELD_INTEGRITY_ALGO;
                break;

            case CERT_STORAGE_TAG_INTEGRITY_VALUE:
                cert_storage_ctx->integrity_value = cmd_ptr;
                fields_present_cntr |= CERT_FIELD_INTEGRITY_VALUE;
                break;

            default:
                return kStatus_CSR_INVALID_FORMAT;
        }
        cmd_ptr += length;
    }

    // Check if all required fields are present
    if ((fields_present_cntr & CERT_ALL_REQUIRED_FIELDS) != CERT_ALL_REQUIRED_FIELDS)
    {
        return kStatus_CSR_TLV_FIELD_MISSING;
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