/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "el2go_csr_tlv_parser.h"
#include "byte_utils.h"

const size_t integrity_algo_value_size_map[NR_OF_ALGOS-1] = {
    4U // CRC_32 produces 4 bytes
};

/*! @brief Extract number of bytes from BER encoded length field (bounds-checked).
 *
 * Reads the BER length at *offset within buf[0..buf_len-1] and advances *offset
 * past the length bytes. The function also verifies that the value field indicated
 * by the extracted length fits within the remaining buffer space.
 *
 * @param[in]  buf       Buffer containing the BER-encoded TLV stream.
 * @param[in]  buf_len   Total valid length of buf.
 * @param[in,out] offset Current position in buf; advanced past the length field on success.
 * @param[out] out_length Extracted length value.
 * @retval kStatus_CSR_SUCCESS             Length parsed successfully.
 * @retval kStatus_CSR_CONF_BUF_SIZE_ERR  Length field or value would exceed buf_len.
 * @retval kStatus_CSR_INVALID_FORMAT     Long-form num_length_bytes is 0 or >4.
 */
static csr_parser_status_t parse_ber_length(const uint8_t *buf, size_t buf_len,
                                            size_t *offset, size_t *out_length)
{
    size_t length = 0u;

    if ((buf == NULL) || (offset == NULL) || (out_length == NULL))
    {
        return kStatus_CSR_INVALID_FORMAT;
    }

    if (*offset >= buf_len)
    {
        return kStatus_CSR_CONF_BUF_SIZE_ERR;
    }

    uint8_t first_byte = buf[(*offset)++];

    if ((first_byte & 0x80u) == 0u)
    {
        /* Short form: length is encoded in bits 0-6 (0-127). */
        length = (size_t)first_byte;
    }
    else
    {
        /* Long form: bits 0-6 indicate number of subsequent length bytes. */
        uint8_t num_length_bytes = first_byte & 0x7Fu;

        if (num_length_bytes == 0u || num_length_bytes > 4u)
        {
            return kStatus_CSR_INVALID_FORMAT;
        }

        for (uint8_t i = 0u; i < num_length_bytes; i++)
        {
            if (*offset >= buf_len)
            {
                return kStatus_CSR_CONF_BUF_SIZE_ERR;
            }
            length = (length << 8u) | (size_t)buf[(*offset)++];
        }
    }

    /* Verify the value field fits within the remaining buffer. */
    if ((*offset + length) > buf_len)
    {
        return kStatus_CSR_CONF_BUF_SIZE_ERR;
    }

    *out_length = length;
    return kStatus_CSR_SUCCESS;
}

/*! @brief Parse buffer to spot EL2GO config block used for CSR generation.
 *
 * Internal function. Parses the TLV stream within conf_buf_ptr[0..conf_buf_len-1]
 * and populates csr_gen_ctx. Unknown or optional tags are skipped to allow
 * forward-compatible extensions. The integrity-covered length (byte offset of the
 * INTEGRITY_VALUE tag) is written to *integrity_covered_len on success.
 *
 * @param[in, out] csr_gen_ctx: Structure to be filled with parsed configuration data.
 * @param[in] conf_buf_ptr: Pointer to base address of the configuration block.
 * @param[in] conf_buf_len: Number of valid bytes in the configuration block.
 * @param[out] integrity_covered_len: Offset of the INTEGRITY_VALUE tag byte.
 * @retval kStatus_CSR_SUCCESS Upon success.
 */
static csr_parser_status_t parse_buffer_csr(csr_gen_context_t *csr_gen_ctx,
                                             const uint8_t *conf_buf_ptr,
                                             size_t conf_buf_len,
                                             size_t *integrity_covered_len)
{
    csr_parser_status_t status = kStatus_CSR_SUCCESS;
    uint8_t tag    = 0U;
    size_t length  = 0U;
    size_t fields_present_cntr = 0U;
    size_t offset  = 0U;
    size_t integrity_value_len = 0U;
    bool done = false;

    if ((csr_gen_ctx == NULL) || (conf_buf_ptr == NULL) || (integrity_covered_len == NULL))
    {
        return kStatus_CSR_INVALID_FORMAT;
    }

    while (offset < conf_buf_len)
    {
        tag = conf_buf_ptr[offset++];

        switch (tag)
        {
            case CSR_GEN_TAG_MAGIC:
                status = parse_ber_length(conf_buf_ptr, conf_buf_len, &offset, &length);
                if (status != kStatus_CSR_SUCCESS) { return status; }
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
                status = parse_ber_length(conf_buf_ptr, conf_buf_len, &offset, &length);
                if (status != kStatus_CSR_SUCCESS) { return status; }
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
                status = parse_ber_length(conf_buf_ptr, conf_buf_len, &offset, &length);
                if (status != kStatus_CSR_SUCCESS) { return status; }
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
                status = parse_ber_length(conf_buf_ptr, conf_buf_len, &offset, &length);
                if (status != kStatus_CSR_SUCCESS) { return status; }
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
                status = parse_ber_length(conf_buf_ptr, conf_buf_len, &offset, &length);
                if (status != kStatus_CSR_SUCCESS) { return status; }
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

            case CSR_GEN_TAG_INTEGRITY_ALGORITHM:
                status = parse_ber_length(conf_buf_ptr, conf_buf_len, &offset, &length);
                if (status != kStatus_CSR_SUCCESS) { return status; }
                if (length != CSR_GEN_INTEGRITY_ALGORITHM_LEN)
                {
                    return kStatus_CSR_INVALID_FORMAT;
                }
                csr_gen_ctx->integrity_algorithm =
                    (integrity_algorithms_t)(get_uint32_val(&conf_buf_ptr[offset]));

                if (!csr_gen_ctx->integrity_algorithm ||
                    csr_gen_ctx->integrity_algorithm >= NR_OF_ALGOS)
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
                status = parse_ber_length(conf_buf_ptr, conf_buf_len, &offset, &length);
                if (status != kStatus_CSR_SUCCESS) { return status; }
                /* Record the end of the length field as the CRC-covered length.
                 * CRC covers tag byte + length byte(s); offset now points to value. */
                *integrity_covered_len = offset;

                /* Save length for post-loop validation (algorithm may not be seen yet). */
                integrity_value_len = length;
                csr_gen_ctx->integrity_value = &conf_buf_ptr[offset];

                if (fields_present_cntr & CSR_FIELD_INTEGRITY_VALUE)
                {
                    return kStatus_CSR_INVALID_FORMAT;
                }
                fields_present_cntr |= CSR_FIELD_INTEGRITY_VALUE;
                /* INTEGRITY_VALUE is always the last field */
                done = true;
                break;

            case CSR_GEN_TAG_ENCODING:
                /* Optional encoding tag: 1 byte, PEM=1, DER=2. */
                status = parse_ber_length(conf_buf_ptr, conf_buf_len, &offset, &length);
                if (status != kStatus_CSR_SUCCESS) { return status; }
                if (length != CSR_GEN_ENCODING_LEN)
                {
                    return kStatus_CSR_INVALID_FORMAT;
                }
                {
                    uint8_t enc = conf_buf_ptr[offset];
                    if (enc != CSR_GEN_ENCODING_PEM && enc != CSR_GEN_ENCODING_DER)
                    {
                        return kStatus_CSR_NOT_SUPPORTED;
                    }
                    csr_gen_ctx->encoding = enc;
                }
                break;

            default:
                /* Unknown or future-use tag: read its length and skip the value.
                 * BER requires forward compatibility; this is NOT an error. */
                status = parse_ber_length(conf_buf_ptr, conf_buf_len, &offset, &length);
                if (status != kStatus_CSR_SUCCESS) { return status; }
                break;
        }
        offset += length;

        if (done)
        {
            break;
        }
    }

    /* Post-loop validation: check all required fields were seen. */
    if ((fields_present_cntr & CSR_ALL_REQUIRED_FIELDS) != CSR_ALL_REQUIRED_FIELDS)
    {
        return kStatus_CSR_TLV_FIELD_MISSING;
    }

    /* integrity_algorithm is now guaranteed valid (1..NR_OF_ALGOS-1) -> index in-bounds. */
    if (integrity_value_len !=
            (size_t)integrity_algo_value_size_map[csr_gen_ctx->integrity_algorithm - 1U])
    {
        return kStatus_CSR_INVALID_FORMAT;
    }

    return kStatus_CSR_SUCCESS;
}

/*! @brief Parse buffer to spot EL2GO config block used for x.509 certificate storage.
 *
 * Internal function. Parses the TLV stream within conf_buf_ptr[0..conf_buf_len-1]
 * and populates cert_storage_ctx. Unknown or optional tags are skipped to allow
 * forward-compatible extensions. The integrity-covered length (byte offset of the
 * INTEGRITY_VALUE tag) is written to *integrity_covered_len on success.
 *
 * @param[in, out] cert_storage_ctx: Structure to be filled with parsed configuration data.
 * @param[in] conf_buf_ptr: Pointer to base address of the configuration block.
 * @param[in] conf_buf_len: Number of valid bytes in the configuration block.
 * @param[out] integrity_covered_len: Offset of the INTEGRITY_VALUE tag byte.
 * @retval kStatus_CSR_SUCCESS Upon success.
 */
static csr_parser_status_t parse_buffer_cert(cert_storage_context_t *cert_storage_ctx,
                                              const uint8_t *conf_buf_ptr,
                                              size_t conf_buf_len,
                                              size_t *integrity_covered_len)
{
    csr_parser_status_t status = kStatus_CSR_SUCCESS;
    uint8_t tag    = 0U;
    size_t length  = 0U;
    size_t fields_present_cntr = 0U;
    size_t offset  = 0U;
    size_t integrity_value_len = 0U;
    bool done = false;

    if ((cert_storage_ctx == NULL) || (conf_buf_ptr == NULL) || (integrity_covered_len == NULL))
    {
        return kStatus_CSR_INVALID_FORMAT;
    }

    while (offset < conf_buf_len)
    {
        tag = conf_buf_ptr[offset++];

        switch (tag)
        {
            case CERT_STORAGE_TAG_MAGIC:
                status = parse_ber_length(conf_buf_ptr, conf_buf_len, &offset, &length);
                if (status != kStatus_CSR_SUCCESS) { return status; }
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
                status = parse_ber_length(conf_buf_ptr, conf_buf_len, &offset, &length);
                if (status != kStatus_CSR_SUCCESS) { return status; }
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
                status = parse_ber_length(conf_buf_ptr, conf_buf_len, &offset, &length);
                if (status != kStatus_CSR_SUCCESS) { return status; }
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
                status = parse_ber_length(conf_buf_ptr, conf_buf_len, &offset, &length);
                if (status != kStatus_CSR_SUCCESS) { return status; }
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
                status = parse_ber_length(conf_buf_ptr, conf_buf_len, &offset, &length);
                if (status != kStatus_CSR_SUCCESS) { return status; }
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
                status = parse_ber_length(conf_buf_ptr, conf_buf_len, &offset, &length);
                if (status != kStatus_CSR_SUCCESS) { return status; }
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

            case CERT_STORAGE_TAG_INTEGRITY_ALGORITHM:
                status = parse_ber_length(conf_buf_ptr, conf_buf_len, &offset, &length);
                if (status != kStatus_CSR_SUCCESS) { return status; }
                if (length != CERT_STORAGE_INTEGRITY_ALGORITHM_LEN)
                {
                    return kStatus_CSR_INVALID_FORMAT;
                }
                cert_storage_ctx->integrity_algorithm =
                    (integrity_algorithms_t)(get_uint32_val(&conf_buf_ptr[offset]));

                if (!cert_storage_ctx->integrity_algorithm ||
                    cert_storage_ctx->integrity_algorithm >= NR_OF_ALGOS)
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
                status = parse_ber_length(conf_buf_ptr, conf_buf_len, &offset, &length);
                if (status != kStatus_CSR_SUCCESS) { return status; }
                /* Record the end of the length field as the CRC-covered length.
                 * CRC covers tag byte + length byte(s); offset now points to value. */
                *integrity_covered_len = offset;

                /* Save length for post-loop validation (algorithm may not be seen yet). */
                integrity_value_len = length;
                cert_storage_ctx->integrity_value = &conf_buf_ptr[offset];

                if (fields_present_cntr & CERT_FIELD_INTEGRITY_VALUE)
                {
                    return kStatus_CSR_INVALID_FORMAT;
                }
                fields_present_cntr |= CERT_FIELD_INTEGRITY_VALUE;
                /* INTEGRITY_VALUE is always the last field */
                done = true;
                break;

            default:
                /* Unknown or future-use tag: read its length and skip the value.
                 * BER requires forward compatibility; this is NOT an error. */
                status = parse_ber_length(conf_buf_ptr, conf_buf_len, &offset, &length);
                if (status != kStatus_CSR_SUCCESS) { return status; }
                break;
        }
        offset += length;

        if (done)
        {
            break;
        }
    }

    /* Post-loop validation: check all required fields were seen. */
    if ((fields_present_cntr & CERT_ALL_REQUIRED_FIELDS) != CERT_ALL_REQUIRED_FIELDS)
    {
        return kStatus_CSR_TLV_FIELD_MISSING;
    }

    /* integrity_algorithm is now guaranteed valid (1..NR_OF_ALGOS-1) -> index in-bounds. */
    if (integrity_value_len !=
            (size_t)integrity_algo_value_size_map[cert_storage_ctx->integrity_algorithm - 1U])
    {
        return kStatus_CSR_INVALID_FORMAT;
    }

    return kStatus_CSR_SUCCESS;
}

csr_parser_status_t 
parse_buf_and_fill_context(csr_gen_context_t *csr_gen_ctx,
                           cert_storage_context_t *cert_storage_ctx,
                           const uint8_t *conf_buf_ptr,
                           size_t conf_buf_len,
                           size_t *integrity_covered_len)
{
    if ((!csr_gen_ctx && !cert_storage_ctx) || !conf_buf_ptr || !conf_buf_len || !integrity_covered_len)
    {
        return kStatus_CSR_INVALID_FORMAT;
    }

    if (conf_buf_len < 2U)
    {
        return kStatus_CSR_CONF_BUF_SIZE_ERR;
    }
    const char* magic_val_start = (const char*)(conf_buf_ptr + 2U);

    if (!memcmp(magic_val_start, CSR_GEN_MAGIC_VALUE, CSR_GEN_MAGIC_VALUE_LEN))
    {
        return parse_buffer_csr(csr_gen_ctx, conf_buf_ptr, conf_buf_len, integrity_covered_len);
    }
    else if (!memcmp(magic_val_start, CERT_STORAGE_MAGIC_VALUE, CERT_STORAGE_MAGIC_VALUE_LEN))
    {
        return parse_buffer_cert(cert_storage_ctx, conf_buf_ptr, conf_buf_len, integrity_covered_len);
    }

    return kStatus_CSR_INVALID_FORMAT;
}
