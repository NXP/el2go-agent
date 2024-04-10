/*
 * Copyright 2024 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */


#include <el2go_psa_import.h>

#define MAGIC_TLV_SIZE  0x0D
#define MAGIC_TLV_1     0x400B6564U
#define MAGIC_TLV_2     0x67656C6FU
#define MAGIC_TLV_3     0x636B3267U
#define MAGIC_TLV_4     0x6FU

#define PSA_CMD_TAG_KEY_ID              0x41U
#define PSA_CMD_TAG_PERMITTED_ALGORITHM 0x42U
#define PSA_CMD_TAG_KEY_USAGE_FLAGS     0x43U
#define PSA_CMD_TAG_KEY_TYPE            0x44U
#define PSA_CMD_TAG_KEY_BITS            0x45U
#define PSA_CMD_TAG_KEY_LIFETIME        0x46U
#define PSA_CMD_TAG_SIGNATURE           0x5EU

#define OEM_KEY_ID      0x7FFF817BU
#define RKTH_KEY_ID     0x7FFF817AU
#define OTP_DATA_KEY_ID 0x7FFF817CU


static uint32_t get_uint32_val(const uint8_t *input)
{
    uint32_t output = 0U;
    output          = *(input);
    output <<= 8;
    output |= *(input + 1);
    output <<= 8;
    output |= *(input + 2);
    output <<= 8;
    output |= *(input + 3);
    return output;
}

static uint16_t get_uint16_val(const uint8_t *input)
{
    uint16_t output = 0U;
    output          = *input;
    output <<= 8;
    output |= *(input + 1);
    return output;
}

static int get_len(const unsigned char **p, const unsigned char *end, size_t *len)
{
    if ((end - *p) < 1)
        return (PSA_ERROR_INVALID_ARGUMENT);

    if ((**p & 0x80) == 0)
        *len = *(*p)++;
    else
    {
        switch (**p & 0x7F)
        {
            case 1:
                if ((end - *p) < 2)
                    return (PSA_ERROR_INVALID_ARGUMENT);

                *len = (*p)[1];
                (*p) += 2;
                break;

            case 2:
                if ((end - *p) < 3)
                    return (PSA_ERROR_INVALID_ARGUMENT);

                *len = ((size_t)(*p)[1] << 8) | (*p)[2];
                (*p) += 3;
                break;

            case 3:
                if ((end - *p) < 4)
                    return (PSA_ERROR_INVALID_ARGUMENT);

                *len = ((size_t)(*p)[1] << 16) | ((size_t)(*p)[2] << 8) | (*p)[3];
                (*p) += 4;
                break;

            case 4:
                if ((end - *p) < 5)
                    return (PSA_ERROR_INVALID_ARGUMENT);

                *len = ((size_t)(*p)[1] << 24) | ((size_t)(*p)[2] << 16) | ((size_t)(*p)[3] << 8) | (*p)[4];
                (*p) += 5;
                break;

            default:
                return (PSA_ERROR_INVALID_ARGUMENT);
        }
    }
    if (*len > (size_t)(end - *p))
        return (PSA_ERROR_INVALID_ARGUMENT);

    return (0);
}

static int get_tag(const unsigned char **p, const unsigned char *end, size_t *len, int tag)
{
    if ((end - *p) < 1)
        return (PSA_ERROR_INVALID_ARGUMENT);

    if (**p != tag)
        return (PSA_ERROR_INVALID_ARGUMENT);

    (*p)++;

    return (get_len(p, end, len));
}

psa_status_t iot_agent_utils_parse_blob(const uint8_t *blob, size_t blob_size, psa_key_attributes_t *attributes, size_t *actual_blob_size)
{
    psa_status_t agent_status = PSA_SUCCESS;

    uint8_t tag    = 0U; // the tag of the current TLV
    size_t cmd_len = 0U; // the length of the current TLV

    const uint8_t *cmd_ptr = NULL;
    const uint8_t *end     = NULL;

    if ( blob == NULL )
      LOG("blob address is NULL\r\n");
    if ( attributes == NULL )
       LOG("attributes address is NULL\r\n");
    if ( actual_blob_size == NULL )
       LOG("actual_blob_size is NULL\r\n");

    *attributes = psa_key_attributes_init();

    cmd_ptr = blob;
    end     = cmd_ptr + blob_size;

    while ((cmd_ptr + 1) < end)
    {
        tag = *cmd_ptr;
        psa_status_t psa_status = get_tag(&cmd_ptr, end, &cmd_len, tag);
        if( psa_status != PSA_SUCCESS)
          LOG("Get_tag failed (%d)\r\n", psa_status);

        switch (tag)
        {
            case PSA_CMD_TAG_KEY_ID:
                psa_set_key_id(attributes, mbedtls_svc_key_id_make(0, (psa_key_id_t)get_uint32_val(cmd_ptr)));
                break;
            case PSA_CMD_TAG_PERMITTED_ALGORITHM:
                psa_set_key_algorithm(attributes, (psa_algorithm_t)get_uint32_val(cmd_ptr));
                break;
            case PSA_CMD_TAG_KEY_USAGE_FLAGS:
                psa_set_key_usage_flags(attributes, (psa_key_usage_t)get_uint32_val(cmd_ptr));
                break;
            case PSA_CMD_TAG_KEY_TYPE:
                psa_set_key_type(attributes, (psa_key_type_t)get_uint16_val(cmd_ptr));
                break;
            case PSA_CMD_TAG_KEY_BITS:
                psa_set_key_bits(attributes, (size_t)get_uint32_val(cmd_ptr));
                break;
            case PSA_CMD_TAG_KEY_LIFETIME:
                psa_set_key_lifetime(attributes, (psa_key_lifetime_t)get_uint32_val(cmd_ptr));
                break;
            case PSA_CMD_TAG_SIGNATURE:
                // Handle blobs with longer than actual size (we can count on this being the last tag)
				*actual_blob_size = (cmd_ptr + cmd_len) - blob;
                goto exit;
            default:
                break;
        }
        cmd_ptr += cmd_len;
    }

exit:
    return agent_status;
}

static bool is_blob_magic(const uint8_t *ptr, const uint8_t *end)
{
    if (ptr + MAGIC_TLV_SIZE >= end)
        return false;

    // The magic TLV is 104 bits long, sufficient to not randomly appear inside the blob (for practical purposes)
    return get_uint32_val(ptr)     == MAGIC_TLV_1 &&
           get_uint32_val(ptr + 4) == MAGIC_TLV_2 &&
           get_uint32_val(ptr + 8) == MAGIC_TLV_3 &&
           *(ptr + 12)             == MAGIC_TLV_4;
}

psa_status_t iot_agent_utils_psa_import_blobs_from_flash(const uint8_t *blob_area, size_t blob_area_size, size_t *blobs_imported)
{
    psa_status_t psa_import_status = PSA_SUCCESS;

    if ( blob_area == NULL )
      LOG("blob_area address is NULL\r\n");
    if ( blobs_imported == NULL )
      LOG("blobs_imported address is NULL\r\n");

    *blobs_imported = 0U;

    const uint8_t* blob_area_end = blob_area + blob_area_size;
    if ( !(is_blob_magic(blob_area, blob_area_end)) )
    {
        psa_import_status = PSA_SUCCESS;
        goto exit;
    }

    uint8_t *blob_ptr = (uint8_t *)blob_area;

    do {
        uint8_t *blob = blob_ptr;
        do {
            blob_ptr++;
        } while (!is_blob_magic(blob_ptr, blob_area_end) && blob_ptr < blob_area_end);

        // This will be longer than the actual blob size for the last blob (handled by the blob parser)
        size_t blob_size = blob_ptr - blob;
        psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
        psa_import_status = iot_agent_utils_parse_blob(blob, blob_size, &attributes, &blob_size);
        if ( psa_import_status != PSA_SUCCESS)
        {
            LOG("Failed to parse blob attributes\r\n");
            goto exit;
        }
        
        psa_key_id_t blob_key_id = psa_get_key_id(&attributes);
        if (blob_key_id == OEM_KEY_ID || blob_key_id == RKTH_KEY_ID || blob_key_id == OTP_DATA_KEY_ID) {
            continue;
        }

        psa_key_id_t psa_key_id = PSA_KEY_ID_NULL;
        psa_status_t psa_status = psa_import_key(&attributes, blob, blob_size, &psa_key_id);
        if (psa_status == PSA_ERROR_ALREADY_EXISTS) {
            psa_status = psa_destroy_key(blob_key_id);
            psa_status = psa_import_key(&attributes, blob, blob_size, &psa_key_id);
        }
        if ( psa_status != PSA_SUCCESS)
        {
          LOG("psa_import_key failed (%d)\r\n", psa_status);
          psa_import_status = psa_status;
          goto exit;
        }
        
        (*blobs_imported)++;
    } while (blob_ptr < blob_area_end);

exit:
    return psa_import_status;
}