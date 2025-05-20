/*
 * Copyright 2023-2025 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "fsl_common.h"
#include "iot_agent_claimcode_encrypt.h"

#include "fsl_device_registers.h"
#include "nxp_iot_agent_status.h"
#include "mcuxClEls_KeyManagement.h"
#include "mcuxClEls_Rng.h"
#include "mcuxClAes.h"
#include "mcuxClEls_Ecc.h"
#include "mcuxClEls_Kdf.h"
#include "mcuxClEls_Cipher.h"
#include "mcuxClEls_Cmac.h"
#include "stdint.h"
#include "stdbool.h"
#include "string.h"

#ifdef __ZEPHYR__
#include <zephyr/drivers/hwinfo.h>
#include <stdio.h>
#define LOG printf
#else
#include <fsl_silicon_id.h>
#include <fsl_debug_console.h>
#define LOG PRINTF
#endif
/*******************************************************************************
 * Definitions
 ******************************************************************************/
#define UID_FUSE_IDX                46U
#define UID_SIZE                    16U
#define IV_SIZE                     16U
#define AES_BLOCK_SIZE              16U
#define PADDED_CLAIM_CODE_MAX_SIZE  112U

/*******************************************************************************
 * Prototypes
 ******************************************************************************/

/*******************************************************************************
 * Code
 ******************************************************************************/

static const mcuxClEls_KeyProp_t keypair_prop = {
    .bits = 
    {
        .upprot_priv    = MCUXCLELS_KEYPROPERTY_PRIVILEGED_TRUE,
        .upprot_sec     = MCUXCLELS_KEYPROPERTY_SECURE_TRUE,
        .ksize          = MCUXCLELS_KEYPROPERTY_KEY_SIZE_256,
    }
};

static const mcuxClEls_KeyProp_t shared_secret_prop = {
    .bits =
        {
            .upprot_priv = MCUXCLELS_KEYPROPERTY_PRIVILEGED_TRUE,
            .upprot_sec  = MCUXCLELS_KEYPROPERTY_SECURE_TRUE,
            .uckdf       = MCUXCLELS_KEYPROPERTY_CKDF_TRUE,
            .ksize       = MCUXCLELS_KEYPROPERTY_KEY_SIZE_128,
        },
};

static const mcuxClEls_KeyProp_t enc_key_prop = {
    .bits =
        {
            .upprot_priv = MCUXCLELS_KEYPROPERTY_PRIVILEGED_TRUE,
            .upprot_sec  = MCUXCLELS_KEYPROPERTY_SECURE_TRUE,
            .uaes        = MCUXCLELS_KEYPROPERTY_AES_TRUE,
            .ksize       = MCUXCLELS_KEYPROPERTY_KEY_SIZE_128,
            .kactv       = MCUXCLELS_KEYPROPERTY_ACTIVE_TRUE,
        },
};

static const uint8_t ckdf_derivation_data_enc[12] = {
    0x43, 0x43, 0x5f, 0x45, 0x4E, 0x43, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static const mcuxClEls_KeyProp_t mac_key_prop = {
    .bits =
        {
            .upprot_priv = MCUXCLELS_KEYPROPERTY_PRIVILEGED_TRUE,
            .upprot_sec  = MCUXCLELS_KEYPROPERTY_SECURE_TRUE,
            .ucmac       = MCUXCLELS_KEYPROPERTY_CMAC_TRUE,
            .ksize       = MCUXCLELS_KEYPROPERTY_KEY_SIZE_128,
            .kactv       = MCUXCLELS_KEYPROPERTY_ACTIVE_TRUE,
        },
};

static const uint8_t ckdf_derivation_data_mac[12] = {
    0x43, 0x43, 0x5f, 0x4d, 0x41, 0x43, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

#define PLOG_DEBUG(...)
#define PLOG_INFO(...)  LOG(__VA_ARGS__)
#define PLOG_ERROR(...) LOG(__VA_ARGS__)

static const char nibble_to_char[16] = {
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
};

static void printf_buffer(const char *name, const unsigned char *buffer, size_t size)
{
#define PP_BYTES_PER_LINE (32U)
    char line_buffer[PP_BYTES_PER_LINE * 2U + 2U];
    const unsigned char *pos = buffer;
    size_t remaining         = size;
    while (remaining > 0U)
    {
        size_t block_size = remaining > PP_BYTES_PER_LINE ? PP_BYTES_PER_LINE : remaining;
        uint32_t len      = 0U;
        for (size_t i = 0U; i < block_size; i++)
        {
            line_buffer[len++] = nibble_to_char[((*pos) & 0xf0U) >> 4U];
            line_buffer[len++] = nibble_to_char[(*pos++) & 0x0fU];
        }
        line_buffer[len++] = '\n';
        line_buffer[len] = '\0';
        LOG("%s (0x%p): %s", name, pos, line_buffer);
        remaining -= block_size;
    }
}

static size_t ceil_to_aes_blocksize(size_t size)
{
    if (size > SIZE_MAX - (AES_BLOCK_SIZE - 1U))
    {
        LOG("Possible wrap in the size\n");
        return size;
    }
    return ((size + (AES_BLOCK_SIZE - 1U)) & (~(AES_BLOCK_SIZE - 1U)));
}

static iot_agent_status_t read_uid(uint8_t *uid)
{
    uint32_t uid_len = UID_SIZE;
#ifdef __ZEPHYR__
    hwinfo_get_device_id(uid, uid_len);
#else
    if (SILICONID_GetID(uid, &uid_len) != kStatus_Success)
    {
        return IOT_AGENT_FAILURE;
    }
#endif
    return IOT_AGENT_SUCCESS;
}

static bool is_active_keyslot(mcuxClEls_KeyIndex_t keyIdx)
{
    mcuxClEls_KeyProp_t key_properties;
    key_properties.word.value = ((const volatile uint32_t *)(&ELS->ELS_KS0))[keyIdx];
    return (key_properties.bits.kactv == MCUXCLCSS_KEYPROPERTY_ACTIVE_TRUE);
}

static inline uint32_t get_required_keyslots(mcuxClEls_KeyProp_t prop)
{
    return prop.bits.ksize == MCUXCLELS_KEYPROPERTY_KEY_SIZE_128 ? 1U : 2U;
}

static mcuxClEls_KeyIndex_t get_free_keyslot(uint32_t required_keyslots)
{
    if (required_keyslots > MCUXCLELS_KEY_SLOTS)
    {
        return MCUXCLELS_KEY_SLOTS;
    }
    for (mcuxClEls_KeyIndex_t keyIdx = 0U; keyIdx <= (MCUXCLELS_KEY_SLOTS - required_keyslots); keyIdx++)
    {
        bool is_valid_keyslot = true;
        for (uint32_t i = 0U; i < required_keyslots; i++)
        {
            if (is_active_keyslot(keyIdx + i))
            {
                is_valid_keyslot = false;
                break;
            }
        }

        if (is_valid_keyslot)
        {
            return keyIdx;
        }
    }
    return MCUXCLELS_KEY_SLOTS;
}

static iot_agent_status_t generate_keypair(mcuxClEls_KeyIndex_t *dst_key_index,
                                           uint8_t *public_key,
                                           size_t *public_key_size)
{
    if (*public_key_size < 64U)
    {
        PLOG_ERROR("insufficient space for public key");
        return IOT_AGENT_FAILURE;
    }

    mcuxClEls_EccKeyGenOption_t options = {0};
    options.bits.kgsrc                  = MCUXCLELS_ECC_OUTPUTKEY_RANDOM;
    options.bits.kgtypedh               = MCUXCLELS_ECC_OUTPUTKEY_KEYEXCHANGE;

    uint32_t keypair_required_keyslots = get_required_keyslots(keypair_prop);
    *dst_key_index                     = (mcuxClEls_KeyIndex_t)get_free_keyslot(keypair_required_keyslots);

    if (!(*dst_key_index < MCUXCLELS_KEY_SLOTS))
    {
        PLOG_ERROR("no free keyslot found");
        return IOT_AGENT_FAILURE;
    }

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(
        result, token,
        mcuxClEls_EccKeyGen_Async(options, (mcuxClEls_KeyIndex_t)0U, *dst_key_index, keypair_prop, NULL, public_key));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_EccKeyGen_Async) != token) || (MCUXCLELS_STATUS_OK_WAIT != result))
    {
        PLOG_ERROR("mcuxClEls_EccKeyGen_Async failed: 0x%08x\n", result);
        return IOT_AGENT_FAILURE;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClEls_WaitForOperation(MCUXCLELS_ERROR_FLAGS_CLEAR));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_WaitForOperation) != token) || (MCUXCLELS_STATUS_OK != result))
    {
        PLOG_ERROR("mcuxClEls_WaitForOperation failed: 0x%08x\n", result);
        return IOT_AGENT_FAILURE;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    *public_key_size = 64;
    return IOT_AGENT_SUCCESS;
}

static iot_agent_status_t perform_key_agreement(mcuxClEls_KeyIndex_t keypair_index,
                                                mcuxClEls_KeyProp_t shared_secret_properties,
                                                mcuxClEls_KeyIndex_t *dst_key_index,
                                                const uint8_t *public_key,
                                                size_t public_key_size)
{
    uint32_t shared_secret_required_keyslots = get_required_keyslots(shared_secret_properties);
    *dst_key_index                           = get_free_keyslot(shared_secret_required_keyslots);

    if (!(*dst_key_index < MCUXCLELS_KEY_SLOTS))
    {
        PLOG_ERROR("no free keyslot found");
        return IOT_AGENT_FAILURE;
    }

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(
        result, token, mcuxClEls_EccKeyExchange_Async(keypair_index, public_key, *dst_key_index, shared_secret_properties));

    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_EccKeyExchange_Async) != token) || (MCUXCLELS_STATUS_OK_WAIT != result))
    {
        PLOG_ERROR("mcuxClEls_EccKeyExchange_Async failed: 0x%08x\n", result);
        return IOT_AGENT_FAILURE;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClEls_WaitForOperation(MCUXCLELS_ERROR_FLAGS_CLEAR));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_WaitForOperation) != token) || (MCUXCLELS_STATUS_OK != result))
    {
        PLOG_ERROR("mcuxClEls_WaitForOperation failed: 0x%08x\n", result);
        return IOT_AGENT_FAILURE;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    return IOT_AGENT_SUCCESS;
}

static iot_agent_status_t derive_key(mcuxClEls_KeyIndex_t src_key_index,
                                     mcuxClEls_KeyProp_t key_prop,
                                     const uint8_t *dd,
                                     mcuxClEls_KeyIndex_t *dst_key_index)
{
    uint32_t required_keyslots = get_required_keyslots(key_prop);

    *dst_key_index = get_free_keyslot(required_keyslots);

    if (!(*dst_key_index < MCUXCLELS_KEY_SLOTS))
    {
        PLOG_ERROR("no free keyslot found");
        return IOT_AGENT_FAILURE;
    }

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token,
                                     mcuxClEls_Ckdf_Sp800108_Async(src_key_index, *dst_key_index, key_prop, dd));

    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Ckdf_Sp800108_Async) != token) || (MCUXCLELS_STATUS_OK_WAIT != result))
    {
        PLOG_ERROR("mcuxClEls_Ckdf_Sp800108_Async failed: 0x%08x\n", result);
        return IOT_AGENT_FAILURE;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClEls_WaitForOperation(MCUXCLELS_ERROR_FLAGS_CLEAR));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_WaitForOperation) != token) || (MCUXCLELS_STATUS_OK != result))
    {
        PLOG_ERROR("mcuxClEls_WaitForOperation failed: 0x%08x\n", result);
        return IOT_AGENT_FAILURE;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();
    return IOT_AGENT_SUCCESS;
}

static iot_agent_status_t delete_key(mcuxClEls_KeyIndex_t key_index)
{
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClEls_KeyDelete_Async(key_index));

    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_KeyDelete_Async) != token) || (MCUXCLELS_STATUS_OK_WAIT != result))
    {
        PLOG_ERROR("mcuxClEls_KeyDelete_Async failed: 0x%08x\n", result);
        return IOT_AGENT_FAILURE;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClEls_WaitForOperation(MCUXCLELS_ERROR_FLAGS_CLEAR));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_WaitForOperation) != token) || (MCUXCLELS_STATUS_OK != result))
    {
        PLOG_ERROR("mcuxClEls_WaitForOperation failed: 0x%08x\n", result);
        return IOT_AGENT_FAILURE;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();
    return IOT_AGENT_SUCCESS;
}

static iot_agent_status_t generate_iv(uint8_t *iv)
{
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClCss_Rng_DrbgRequest_Async(iv, IV_SIZE));

    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClCss_Rng_DrbgRequest_Async) != token) ||
        (MCUXCLCSS_STATUS_OK_WAIT != result))
    {
        PLOG_ERROR("mcuxClCss_Rng_DrbgRequest_Async failed: 0x%08x\n", result);
        return IOT_AGENT_FAILURE;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClEls_WaitForOperation(MCUXCLELS_ERROR_FLAGS_CLEAR));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_WaitForOperation) != token) || (MCUXCLELS_STATUS_OK != result))
    {
        PLOG_ERROR("mcuxClEls_WaitForOperation failed: 0x%08x\n", result);
        return IOT_AGENT_FAILURE;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();
    return IOT_AGENT_SUCCESS;
}

static iot_agent_status_t encrypt_claimcode(mcuxClEls_KeyIndex_t shared_secret_index,
                                            const char *plain_claimcode,
                                            const uint8_t *iv,
                                            uint8_t *encrypted_claimcode)
{
    uint8_t padded_plain_claimcode[PADDED_CLAIM_CODE_MAX_SIZE] = {0U}; // Max claimcode length is 100 characters.
    size_t plain_claimcode_len           = strlen(plain_claimcode);
    size_t encrypted_claimcode_len       = 0U;

    if (plain_claimcode_len > (SIZE_MAX - 1U))
    {
        PLOG_ERROR("Error in the plain claim code size\n");
        return IOT_AGENT_FAILURE;
    }
    encrypted_claimcode_len = ceil_to_aes_blocksize(plain_claimcode_len + 1U);
    mcuxClEls_KeyIndex_t enc_key_index   = 0U;
    iot_agent_status_t agent_status =
        derive_key(shared_secret_index, enc_key_prop, ckdf_derivation_data_enc, &enc_key_index);
    if (IOT_AGENT_SUCCESS != agent_status)
    {
        PLOG_ERROR("derive_key failed: 0x%08x\n", agent_status);
        return IOT_AGENT_FAILURE;
    }

    mcuxClEls_CipherOption_t cipher_options = {0U};
    cipher_options.bits.cphmde              = MCUXCLELS_CIPHERPARAM_ALGORITHM_AES_CBC;
    cipher_options.bits.dcrpt               = MCUXCLELS_CIPHER_ENCRYPT;
    cipher_options.bits.extkey              = MCUXCLELS_CIPHER_INTERNAL_KEY;

    if (plain_claimcode_len >= PADDED_CLAIM_CODE_MAX_SIZE)
    {
        PLOG_ERROR("Error in plain claim code size");
        return IOT_AGENT_FAILURE;
    }
    memcpy(padded_plain_claimcode, plain_claimcode, plain_claimcode_len);
    padded_plain_claimcode[plain_claimcode_len] = 0x80U;

    // The ELS will not write to the location of the IV with the given ciper options, therefore it is safe to cast away
    // the const here.
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(
        result, token,
        mcuxClEls_Cipher_Async(cipher_options, enc_key_index, NULL, 0, padded_plain_claimcode, encrypted_claimcode_len,
                               (uint8_t *)iv, encrypted_claimcode));

    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Cipher_Async) != token) || (MCUXCLELS_STATUS_OK_WAIT != result))
    {
        PLOG_ERROR("mcuxClEls_Cipher_Async failed: 0x%08x\n", result);
        return IOT_AGENT_FAILURE;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClEls_WaitForOperation(MCUXCLELS_ERROR_FLAGS_CLEAR));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_WaitForOperation) != token) || (MCUXCLELS_STATUS_OK != result))
    {
        PLOG_ERROR("mcuxClEls_WaitForOperation failed: 0x%08x\n", result);
        return IOT_AGENT_FAILURE;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    agent_status = delete_key(enc_key_index);
    if (IOT_AGENT_SUCCESS != agent_status)
    {
        PLOG_ERROR("delete_key failed: 0x%08x", agent_status);
        return IOT_AGENT_FAILURE;
    }

    return IOT_AGENT_SUCCESS;
}

static iot_agent_status_t cmac_claimcode(mcuxClEls_KeyIndex_t shared_secret_index,
                                         uint8_t *claimcode_blob,
                                         uint32_t claimcode_blob_length_before_mac)
{
    uint8_t *pos                         = &claimcode_blob[claimcode_blob_length_before_mac];
    uint8_t mac[AES_BLOCK_SIZE]          = {0U};
    uint32_t missing_bytes_to_fill_block = AES_BLOCK_SIZE - (claimcode_blob_length_before_mac % AES_BLOCK_SIZE);
    // ELS needs us to pad the message, it does not do that itself :-(
    if (missing_bytes_to_fill_block != 0U)
    {
        memset(pos, 0, missing_bytes_to_fill_block);
        *pos = 0x80U;
    }

    mcuxClEls_KeyIndex_t mac_key_index = 13U;
    iot_agent_status_t agent_status =
        derive_key(shared_secret_index, mac_key_prop, ckdf_derivation_data_mac, &mac_key_index);
    if (IOT_AGENT_SUCCESS != agent_status)
    {
        PLOG_ERROR("derive_key failed: 0x%08x\n", agent_status);
        return IOT_AGENT_FAILURE;
    }

    mcuxClEls_CmacOption_t cmac_options = {0U};
    cmac_options.bits.initialize        = MCUXCLELS_CMAC_INITIALIZE_ENABLE;
    cmac_options.bits.finalize          = MCUXCLELS_CMAC_FINALIZE_ENABLE;
    cmac_options.bits.extkey            = MCUXCLELS_CMAC_EXTERNAL_KEY_DISABLE;

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token,
                                     mcuxClEls_Cmac_Async(cmac_options, mac_key_index, NULL, 0, claimcode_blob,
                                                          claimcode_blob_length_before_mac, mac));

    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Cmac_Async) != token) || (MCUXCLELS_STATUS_OK_WAIT != result))
    {
        PLOG_ERROR("mcuxClEls_Cmac_Async failed: 0x%08x\n", result);
        return IOT_AGENT_FAILURE;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClEls_WaitForOperation(MCUXCLELS_ERROR_FLAGS_CLEAR));
    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_WaitForOperation) != token) || (MCUXCLELS_STATUS_OK != result))
    {
        PLOG_ERROR("mcuxClEls_WaitForOperation failed: 0x%08x\n", result);
        return IOT_AGENT_FAILURE;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    agent_status = delete_key(mac_key_index);
    if (IOT_AGENT_SUCCESS != agent_status)
    {
        PLOG_ERROR("delete_key failed: 0x%08x", agent_status);
        return IOT_AGENT_FAILURE;
    }

    memcpy(pos, mac, sizeof(mac));
    return IOT_AGENT_SUCCESS;
}

iot_agent_status_t iot_agent_claimcode_encrypt(const char *claimcode,
                                               const uint8_t *el2go_public_key,
                                               size_t el2go_public_key_size,
                                               uint8_t *claimcode_blob,
                                               size_t *claimcode_blob_size)
{
    iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
    size_t plain_claimcode_len      = strlen(claimcode);
    size_t encrypted_claimcode_len = 0U;

    if (plain_claimcode_len > (SIZE_MAX - 1U))
    {
        PLOG_ERROR("Error in the plain claim code size\n");
        return IOT_AGENT_FAILURE;
    }

    encrypted_claimcode_len = ceil_to_aes_blocksize(plain_claimcode_len + 1U /* padding adds at least one byte */);

    // clang-format off
    size_t claimcode_blob_len = 0U
        + 2U + UID_SIZE 
        + 2U + 65U               // public key
        + 2U + sizeof(uint32_t) // key properties
        + 2U + sizeof(uint32_t) // key properties
        + 2U + IV_SIZE          // IV
        + 2U                    // the encrypted length will be added after wrap check
        + 2U + AES_BLOCK_SIZE;              // CMAC
    // clang-format on

    if (encrypted_claimcode_len > (SIZE_MAX - claimcode_blob_len))
    {
        PLOG_ERROR("Error in the claim code size\n");
        return IOT_AGENT_FAILURE;
    }

    claimcode_blob_len += encrypted_claimcode_len;

    if (*claimcode_blob_size < claimcode_blob_len)
    {
        PLOG_ERROR("claimcode blob buffer too small\n");
        return IOT_AGENT_FAILURE;
    }

    PLOG_INFO("Enabling ELS... ");
    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClEls_Enable_Async());

    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Enable_Async) != token) || (MCUXCLELS_STATUS_OK_WAIT != result))
    {
        PLOG_ERROR("mcuxClEls_Enable_Async failed: 0x%08x\n", result);
        return IOT_AGENT_FAILURE;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();

    MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(result, token, mcuxClEls_WaitForOperation(MCUXCLELS_ERROR_FLAGS_CLEAR));

    if ((MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_WaitForOperation) != token) || (MCUXCLELS_STATUS_OK != result))
    {
        PLOG_ERROR("mcuxClEls_WaitForOperation failed: 0x%08x\n", result);
        return IOT_AGENT_FAILURE;
    }
    MCUX_CSSL_FP_FUNCTION_CALL_END();
    PLOG_INFO("done\n");

    PLOG_INFO("Generating random ECC keypair... ");
    mcuxClEls_KeyIndex_t keypair_index = MCUXCLELS_KEY_SLOTS;
    uint8_t public_key[64]             = {0u};
    size_t public_key_size             = sizeof(public_key);
    agent_status                       = generate_keypair(&keypair_index, &public_key[0], &public_key_size);
    if (IOT_AGENT_SUCCESS != agent_status)
    {
        PLOG_ERROR("generate_keypair failed: 0x%08x\n", agent_status);
        return IOT_AGENT_FAILURE;
    }
    PLOG_INFO("done\n");

    PLOG_INFO("Calculating shared secret... ");
    mcuxClEls_KeyIndex_t shared_secret_index = MCUXCLELS_KEY_SLOTS;
    agent_status = perform_key_agreement(keypair_index, shared_secret_prop, &shared_secret_index, el2go_public_key,
                                         el2go_public_key_size);
    if (IOT_AGENT_SUCCESS != agent_status)
    {
        PLOG_ERROR("perform_key_agreement failed: 0x%08x\n", agent_status);
        delete_key(keypair_index);
        return IOT_AGENT_FAILURE;
    }
    agent_status = delete_key(keypair_index);
    if (IOT_AGENT_SUCCESS != agent_status)
    {
        PLOG_ERROR("delete_key failed: 0x%08x\n", agent_status);
        delete_key(shared_secret_index);
        return IOT_AGENT_FAILURE;
    }
    PLOG_INFO("done\n");

    PLOG_INFO("Creating claimcode blob... ");
    uint8_t *pos = claimcode_blob;

    *pos++       = 0x41U;
    *pos++       = UID_SIZE;
    agent_status = read_uid(pos);
    if (IOT_AGENT_SUCCESS != agent_status)
    {
        PLOG_ERROR("read_uid failed: 0x%08x\n", agent_status);
        delete_key(shared_secret_index);
        return IOT_AGENT_FAILURE;
    }
    pos += UID_SIZE;

    *pos++ = 0x42U;
    *pos++ = sizeof(public_key) + 1U;
    *pos++ = 0x04U; // Indicating uncompressed point format (this is what PSA uses as well).
    memcpy(pos, public_key, sizeof(public_key));
    pos += sizeof(public_key);

    *pos++ = 0x43U;
    *pos++ = 4U;
    *pos++ = (enc_key_prop.word.value >> 24U) & 0xFFU;
    *pos++ = (enc_key_prop.word.value >> 16U) & 0xFFU;
    *pos++ = (enc_key_prop.word.value >> 8U) & 0xFFU;
    *pos++ = (enc_key_prop.word.value) & 0xFFU;

    *pos++ = 0x44U;
    *pos++ = 4U;
    *pos++ = (mac_key_prop.word.value >> 24U) & 0xFFU;
    *pos++ = (mac_key_prop.word.value >> 16U) & 0xFFU;
    *pos++ = (mac_key_prop.word.value >> 8U) & 0xFFU;
    *pos++ = (mac_key_prop.word.value) & 0xFFU;

    *pos++       = 0x45U;
    *pos++       = IV_SIZE;
    uint8_t *iv  = pos; // The IV is filled during encryption
    agent_status = generate_iv(iv);
    if (IOT_AGENT_SUCCESS != agent_status)
    {
        PLOG_ERROR("generate_iv failed: 0x%08x\n", agent_status);
        delete_key(shared_secret_index);
        return IOT_AGENT_FAILURE;
    }
    pos += IV_SIZE;

    *pos++                       = 0x46U;

    if (encrypted_claimcode_len > UINT8_MAX)
    {
        PLOG_ERROR("Issue in claim code length\n");
        delete_key(shared_secret_index);
        return IOT_AGENT_FAILURE;
    }

    *pos++                       = encrypted_claimcode_len;
    uint8_t *encrypted_claimcode = pos;
    agent_status                 = encrypt_claimcode(shared_secret_index, claimcode, iv, encrypted_claimcode);
    if (IOT_AGENT_SUCCESS != agent_status)
    {
        PLOG_ERROR("encrypt_claimcode failed: 0x%08x\n", agent_status);
        delete_key(shared_secret_index);
        return IOT_AGENT_FAILURE;
    }

    pos += encrypted_claimcode_len;

    *pos++                                  = 0x5eU;
    *pos++                                  = AES_BLOCK_SIZE;

    if ((pos - claimcode_blob) < 0)
    {
        PLOG_ERROR("Issue in claim code length\n");
        delete_key(shared_secret_index);
        return IOT_AGENT_FAILURE;
    }

    size_t claimcode_blob_length_before_mac = pos - claimcode_blob;
    agent_status = cmac_claimcode(shared_secret_index, claimcode_blob, claimcode_blob_length_before_mac);
    if (IOT_AGENT_SUCCESS != agent_status)
    {
        PLOG_ERROR("cmac_claimcode failed: 0x%08x\n", agent_status);
        delete_key(shared_secret_index);
        return IOT_AGENT_FAILURE;
    }
    pos += AES_BLOCK_SIZE;

    if ((pos - claimcode_blob) < 0)
    {
        PLOG_ERROR("Issue in claim code length\n");
        delete_key(shared_secret_index);
        return IOT_AGENT_FAILURE;
    }

    *claimcode_blob_size = pos - claimcode_blob;

    agent_status = delete_key(shared_secret_index);
    if (IOT_AGENT_SUCCESS != agent_status)
    {
        PLOG_ERROR("delete_key failed: 0x%08x\n", agent_status);
        return IOT_AGENT_FAILURE;
    }
    PLOG_INFO("done\n");

    printf_buffer("claimcode", claimcode_blob, *claimcode_blob_size);
    return IOT_AGENT_SUCCESS;
}
