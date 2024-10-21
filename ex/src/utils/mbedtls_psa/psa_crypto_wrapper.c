/*
 * Copyright 2021-2024 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "nxp_iot_agent_common.h"
#include "nxp_iot_agent.h"
#include "nxp_iot_agent_log.h"
#include "nxp_iot_agent_status.h"
#include "nxp_iot_agent_macros.h"
#include "nxp_iot_agent_macros_psa.h"
#include "nxp_iot_agent_utils.h"
#include "nxp_iot_agent_utils_internal.h"

#undef psa_import_key

#include <string.h>
#include "mbedtls/cmac.h"
#include "mbedtls/nist_kw.h"
#include "mbedtls/asn1.h"
#include "psa_crypto_wrapper.h"
#include "psa/crypto.h"

#define MAX_VALUE_SIZE		255U

// Lengths used in PSA commands
#define PSA_CMD_LENGTH_KEY_ID				4U
#define PSA_CMD_LENGTH_PERMITTED_ALGORITHM	4U
#define PSA_CMD_LENGTH_KEY_USAGE_FLAGS		4U
#define PSA_CMD_LENGTH_KEY_TYPE				2U
#define PSA_CMD_LENGTH_KEY_BITS				4U
#define PSA_CMD_LENGTH_KEY_LIFETIME			4U
#define PSA_CMD_LENGTH_WRAPPING_KEY_ID		4U
#define PSA_CMD_LENGTH_WRAPPING_ALGORITHM	4U
#define PSA_CMD_LENGTH_MAC_KEY_ID			4U
#define PSA_CMD_LENGTH_MAGIC				11U

// Tags used in PSA commands
typedef enum psa_cmd_tag_s {
	PSA_CMD_TAG_MAGIC = 0x40,
	PSA_CMD_TAG_KEY_ID = 0x41,
	PSA_CMD_TAG_PERMITTED_ALGORITHM = 0x42,
	PSA_CMD_TAG_KEY_USAGE_FLAGS = 0x43,
	PSA_CMD_TAG_KEY_TYPE = 0x44,
	PSA_CMD_TAG_KEY_BITS = 0x45,
	PSA_CMD_TAG_KEY_LIFETIME = 0x46,
	PSA_CMD_TAG_WRAPPING_KEY_ID = 0x50,
	PSA_CMD_TAG_WRAPPING_ALGORITHM = 0x51,
	PSA_CMD_TAG_IV = 0x52,
	PSA_CMD_TAG_SIGNATURE_KEY_ID = 0x53,
	PSA_CMD_TAG_SIGNATURE_ALGORITHM = 0x54,
	PSA_CMD_TAG_KEYIN_BLOB = 0x55,
	PSA_CMD_TAG_SIGNATURE = 0x5e
}psa_cmd_tag_t;

#define MAX_KEYINCMD_SIZE	2360U // RSA4096
#define MAX_CMAC_INPUT_FIX_SIZE		12 + \
	PSA_CMD_LENGTH_PERMITTED_ALGORITHM + \
	PSA_CMD_LENGTH_KEY_USAGE_FLAGS + \
	PSA_CMD_LENGTH_KEY_TYPE + \
	PSA_CMD_LENGTH_WRAPPING_ALGORITHM + \
	PSA_CMD_LENGTH_KEY_ID
#define MAX_CMAC_INPUT_SIZE		MAX_CMAC_INPUT_FIX_SIZE + MAX_KEYINCMD_SIZE

// S50 Key properties
#define S50_KEY_PROP_UECSG	0x00020000
#define S50_KEY_PROP_UECDH	0x00040000
#define S50_KEY_PROP_UAES	0x00080000
#define S50_KEY_PROP_UCMAC	0x00001000
#define S50_KEY_PROP_UCKDF	0x00008000
#define S50_KEY_PROP_UHMAC	0x00100000	
#define S50_KEY_PROP_UHKDF	0x00010000

// CMD Key In field size
#define CMD_KEY_IN_S50_PROP_SIZE	4U
#define CMD_KEY_IN_ZEROES_SIZE		4U

// Wrapping Algorithms
#define WRAPPING_ALG_RFC3394		1U
#define WRAPPING_ALG_AES_CBC	    2U
#define WRAPPING_ALG_NONE			3U

// AES CBC
#define AES_CBC_BLOCK_SIZE  		16U

#define	CMD_IN_S50_PROP_OFFSET		0U
#define	CMD_IN_ZEROES_OFFSET		(CMD_IN_S50_PROP_OFFSET + CMD_KEY_IN_S50_PROP_SIZE)
#define	CMD_IN_KEY_OFFSET			(CMD_IN_ZEROES_OFFSET + CMD_KEY_IN_ZEROES_SIZE)

// PSA command context
typedef struct psa_cmd_s {
	psa_key_attributes_t attributes;
	uint8_t* magic;
	size_t magic_size;
	uint32_t wrapping_key_id;
	uint32_t wrapping_algorithm;
	uint8_t* iv;
	size_t iv_size;
	uint32_t signature_key_id;
	uint32_t signature_algorithm;
	uint8_t* keyincmd;
	size_t keyincmd_size;
	uint8_t* signature;
	size_t signature_size;
}psa_cmd_t;

const uint8_t MAGIC[] = { 
	PSA_CMD_TAG_MAGIC,
	PSA_CMD_LENGTH_MAGIC,
    'e', 'd', 'g', 'e', 'l', 'o', 'c', 'k', '2', 'g', 'o', 
};

const uint8_t zeroes[] = { 0x00, 0x00, 0x00, 0x00 };

/** @brief Gets the 32-bit value from the value buffer.
 *
 */
static uint32_t get_uint32_val(const uint8_t* input) {
	uint32_t output = 0U;
	output = *(input);
	output <<= 8;
	output |= *(input + 1);
	output <<= 8;
	output |= *(input + 2);
	output <<= 8;
	output |= *(input + 3);
	return output;
}

/** @brief Gets the 16-bit value from the value buffer.
 *
 */
static uint16_t get_uint16_val(const uint8_t* input) {
	uint16_t output = 0U;
	output = *input;
	output <<= 8;
	output |= *(input + 1);
	return output;
}

/** @brief Gets the 4-byte buffer from the 32-bit value.
 *
 */
static void get_val_from_uint32_t(uint32_t input, uint8_t* output) {
	*output = (input >> 24) & 0x000000FF;
	*(output + 1) = (input >> 16) & 0x000000FF;
	*(output + 2) = (input >> 8) & 0x000000FF;
	*(output + 3) = (input) & 0x000000FF;
}

/** @brief Gets the 2-byte buffer from the 16-bit value.
 *
 */
static void get_val_from_uint16_t(uint16_t input, uint8_t* output) {
	*output = (input >> 8) & 0x000000FF;
	*(output + 1) = (input) & 0x000000FF;
}

/** @brief Initializes the PSA command context.
 *
 * \p psa_cmd is the pointer to context
 */
void psa_cmd_init(psa_cmd_t* psa_cmd) {
	memset(psa_cmd, 0, sizeof(psa_cmd));
	psa_cmd->attributes = psa_key_attributes_init();
	psa_set_key_lifetime(&psa_cmd->attributes, PSA_KEY_LIFETIME_PERSISTENT);
}

/** @brief Parses the command.
 *
 * \p data is the input command buffer
 * \p data_size is the size of the input buffer
 * \p psa_cmd is the output PSA context
 */
static iot_agent_status_t parse_psa_import_cmd(const uint8_t* data, size_t data_size, psa_cmd_t* psa_cmd) {

	iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
	int mbedtls_status = 0;

	uint8_t tag = 0U;    // the tag of the current TLV
	size_t length = 0U;  // the length of the current TLV

	uint8_t* pos = NULL;
	uint8_t* end = NULL;

	ASSERT_OR_EXIT_MSG(data != NULL, "The command is null");
	ASSERT_OR_EXIT_MSG(psa_cmd != NULL, "The key attributes context is null");

	// Unfortunately the mbedtls api is not const-correct, so we need to cast the const away here.
	pos = (uint8_t*) data;
	end = pos + data_size;

	while ((pos + 1) < end) {
		tag = *pos;
		// fills length, pos points to value after a successful call
		mbedtls_status = mbedtls_asn1_get_tag(&pos, end, &length, tag);
		ASSERT_OR_EXIT_MSG(mbedtls_status == 0, "mbedtls_asn1_get_tag failed: 0x%08x", mbedtls_status);
		switch ((psa_cmd_tag_t)tag) {
		case PSA_CMD_TAG_KEY_ID:
			ASSERT_OR_EXIT_MSG(length == PSA_CMD_LENGTH_KEY_ID, "Error in size of PSA_CMD_TAG_KEY_ID");
			psa_set_key_id(&psa_cmd->attributes, (mbedtls_svc_key_id_t)get_uint32_val(pos));
			break;
		case PSA_CMD_TAG_PERMITTED_ALGORITHM:
			ASSERT_OR_EXIT_MSG(length == PSA_CMD_LENGTH_PERMITTED_ALGORITHM, "Error in size of PSA_CMD_TAG_PERMITTED_ALGORITHM");
			psa_set_key_algorithm(&psa_cmd->attributes, (psa_algorithm_t)get_uint32_val(pos));
			break;
		case PSA_CMD_TAG_KEY_USAGE_FLAGS:
			ASSERT_OR_EXIT_MSG(length == PSA_CMD_LENGTH_KEY_USAGE_FLAGS, "Error in size of PSA_CMD_TAG_KEY_USAGE_FLAG");
			psa_set_key_usage_flags(&psa_cmd->attributes, (psa_key_usage_t)get_uint32_val(pos));
			break;
		case PSA_CMD_TAG_KEY_TYPE:
			ASSERT_OR_EXIT_MSG(length == PSA_CMD_LENGTH_KEY_TYPE, "Error in size of PSA_CMD_TAG_KEY_TYPE");
			psa_set_key_type(&psa_cmd->attributes, (psa_key_type_t)get_uint16_val(pos));
			break;
		case PSA_CMD_TAG_KEY_BITS:
			ASSERT_OR_EXIT_MSG(length == PSA_CMD_LENGTH_KEY_BITS, "Error in size of PSA_CMD_TAG_KEY_BITS");
			psa_set_key_bits(&psa_cmd->attributes, (size_t)get_uint32_val(pos));
			break;
		case PSA_CMD_TAG_KEY_LIFETIME:
			ASSERT_OR_EXIT_MSG(length == PSA_CMD_LENGTH_KEY_LIFETIME, "Error in size of PSA_CMD_LENGTH_KEY_LIFETIME");
			//psa_set_key_lifetime(&psa_cmd->attributes, (size_t)get_uint32_val(pos)); Uncomment when using customized psa 
			break;
		case PSA_CMD_TAG_MAGIC:
			ASSERT_OR_EXIT_MSG(length == PSA_CMD_LENGTH_MAGIC, "Error in size of the magic");
			psa_cmd->magic = pos;
			psa_cmd->magic_size = length;
			break;
		case PSA_CMD_TAG_WRAPPING_KEY_ID:
			ASSERT_OR_EXIT_MSG(length == PSA_CMD_LENGTH_WRAPPING_KEY_ID, "Error in size of PSA_CMD_TAG_WRAPPING_KEY_ID");
			psa_cmd->wrapping_key_id = get_uint32_val(pos);
			break;
		case PSA_CMD_TAG_WRAPPING_ALGORITHM:
			ASSERT_OR_EXIT_MSG(length == PSA_CMD_LENGTH_WRAPPING_ALGORITHM, "Error in size of PSA_CMD_TAG_WRAPPING_ALGORITHM");
			psa_cmd->wrapping_algorithm = get_uint32_val(pos);
			break;
		case PSA_CMD_TAG_IV:
			ASSERT_OR_EXIT_MSG(length == MBEDTLS_AES_BLOCK_SIZE, "Error in size of the IV");
			psa_cmd->iv = pos;
			psa_cmd->iv_size = length;
			break;
		case PSA_CMD_TAG_SIGNATURE_KEY_ID:
			ASSERT_OR_EXIT_MSG(length == PSA_CMD_LENGTH_MAC_KEY_ID, "Error in size of PSA_CMD_TAG_SIGNATURE_KEY_ID");
			psa_cmd->signature_key_id = get_uint32_val(pos);
			break;
		case PSA_CMD_TAG_SIGNATURE_ALGORITHM:
			ASSERT_OR_EXIT_MSG(length == PSA_CMD_LENGTH_MAC_KEY_ID, "Error in size of PSA_CMD_TAG_SIGNATURE_ALGORITHM");
			psa_cmd->signature_algorithm = get_uint32_val(pos);
			break;
		case PSA_CMD_TAG_KEYIN_BLOB:
			ASSERT_OR_EXIT_MSG(length <= MAX_KEYINCMD_SIZE, "Error in size of the KEYIN command");
			psa_cmd->keyincmd = pos;
			psa_cmd->keyincmd_size = length;
			break;
		case PSA_CMD_TAG_SIGNATURE:
			ASSERT_OR_EXIT_MSG(length == MBEDTLS_AES_BLOCK_SIZE, "Error in size of the signature");
			psa_cmd->signature = pos;
			psa_cmd->signature_size = length;
			break;
		}
		pos += length;
	}
exit:
	return agent_status;
}

/** @brief Verifies the CMAC data.
 *
 * \p psa_cmd pointer to psa command context
 */
static iot_agent_status_t verify_cmd_cmac(mbedtls_svc_key_id_t key_id, const uint8_t* data, size_t len) {
#if 0	
	
	// This is how it should look like (in mbedtls 3.0.x):
	
	iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
	const size_t cmac_size = 16U;
	ASSERT_OR_EXIT_MSG(len > cmac_size, "Buffer is too small for cmac verification.");

	psa_status_t psa_status = psa_mac_verify(key_id, PSA_ALG_CMAC, data, sizeof(data) - cmac_size, 
		data + len - cmac_size, cmac_size);
	PSA_SUCCESS_OR_EXIT_MSG("psa_mac_verify failed: 0x%08x", psa_status);
#endif

	// As mbedtls 3 is not yet available, fall back to export + pure mbedtls cmac:
	iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
	const mbedtls_cipher_info_t *cipher_info;
	uint8_t calculated_cmac[16] = { 0U };
	uint8_t cmac_key[32] = { 0U };
	size_t cmac_key_length = 0U;

	psa_status_t psa_status = psa_export_key(key_id, &cmac_key[0], sizeof(cmac_key), &cmac_key_length);
	PSA_SUCCESS_OR_EXIT_MSG("psa_export_key failed: 0x%08x", psa_status);
	if (cmac_key_length == 0x10U) {
		cipher_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_ECB);
	} else if (cmac_key_length == 0x20U) {
		cipher_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_ECB);
	}
	else {
		EXIT_STATUS_MSG(IOT_AGENT_FAILURE, "Invalid key size: 0x%08x bytes", cmac_key_length);
	}

	ASSERT_OR_EXIT_MSG(mbedtls_cipher_cmac(cipher_info, cmac_key, cmac_key_length * 8U,
		data, len - sizeof(calculated_cmac), calculated_cmac) == 0, "Error in CMAC execution");

	ASSERT_OR_EXIT_MSG(memcmp(calculated_cmac, data + len - sizeof(calculated_cmac),
                sizeof(calculated_cmac)) == 0, "Error in computing the CMAC cipher");

exit:
	return agent_status;
}

/** @brief Unwraps the key.
 *  client_key variable is freed in upper function.
 * \p psa_cmd pointer to psa command context
 * \p client_key is the buffer including the client key 
 * \p client_key_size size of the client key
 */
static iot_agent_status_t unwrap_key(psa_cmd_t* psa_cmd, uint8_t** client_key, size_t* client_key_size) {
	iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
	mbedtls_nist_kw_context unwrap_ctx;
	uint8_t plain_cmd_in[MAX_KEYINCMD_SIZE];
	size_t plain_cmd_in_size = 0U;
	uint8_t unwrapping_key[32] = { 0U };
	size_t unwrapping_key_length = 0U;

	mbedtls_nist_kw_init(&unwrap_ctx);

	// TODO: when moving to the vendor range, use the unwrapping key ID as is coming from the blob
	psa_status_t psa_status = psa_export_key(EL2GOIMPORT_KEK_SK, &unwrapping_key[0], sizeof(unwrapping_key), &unwrapping_key_length);
	PSA_SUCCESS_OR_EXIT_MSG("psa_export_key failed: 0x%08x", psa_status);

	ASSERT_OR_EXIT_MSG(mbedtls_nist_kw_setkey(&unwrap_ctx, MBEDTLS_CIPHER_ID_AES, unwrapping_key,
		unwrapping_key_length * 8U, MBEDTLS_DECRYPT) == 0,
		"Error in setting the unwrapping key");

	ASSERT_OR_EXIT_MSG(mbedtls_nist_kw_unwrap(&unwrap_ctx, MBEDTLS_KW_MODE_KW, psa_cmd->keyincmd,
		psa_cmd->keyincmd_size, plain_cmd_in, &plain_cmd_in_size, MAX_KEYINCMD_SIZE) == 0,
		"Error in unwrapping the key in command");

	ASSERT_OR_EXIT_MSG(memcmp(zeroes, plain_cmd_in + CMD_IN_ZEROES_OFFSET, CMD_KEY_IN_ZEROES_SIZE) == 0,
		"Error in zeroes field");

	*client_key_size = plain_cmd_in_size - CMD_IN_KEY_OFFSET;

	*client_key = malloc(*client_key_size);

	memcpy(*client_key, plain_cmd_in + CMD_IN_KEY_OFFSET, *client_key_size);

exit:
	mbedtls_nist_kw_free(&unwrap_ctx);
	return agent_status;
}

static  iot_agent_status_t psa_cipher_operation(psa_cipher_operation_t *operation,
	const uint8_t * input,
	size_t input_size,
	size_t part_size,
	uint8_t * output,
	size_t output_size,
	size_t *output_len)
{
	psa_status_t psa_status;
	iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
	size_t bytes_to_write = 0U, bytes_written = 0U, len = 0U;

	*output_len = 0U;
	while (bytes_written != input_size)
	{
		bytes_to_write = (input_size - bytes_written > part_size ?
			part_size :
			input_size - bytes_written);

		psa_status = psa_cipher_update(operation, input + bytes_written,
			bytes_to_write, output + *output_len,
			output_size - *output_len, &len);
		PSA_SUCCESS_OR_EXIT_MSG("psa_cipher_update failed: 0x%08x", psa_status);

		bytes_written += bytes_to_write;
		*output_len += len;
	}

	psa_status = psa_cipher_finish(operation, output + *output_len,
		output_size - *output_len, &len);
	PSA_SUCCESS_OR_EXIT_MSG("psa_cipher_finish failed: 0x%08x", psa_status);
	*output_len += len;

exit:
	return(agent_status);
}

/** @brief Decrypts the key using PSA AES_CBC. The provided cipher text must be ISO 7816-4 padded.
*  client_key variable is freed in upper function.
* \p psa_cmd pointer to psa command context
* \p client_key is the buffer including the client key
* \p client_key_size size of the client key
* \p iv aes cbc inital vector
* \p iv_size aes cbc inital vector size
*/
static iot_agent_status_t decrypt_key(psa_cmd_t* psa_cmd, uint8_t** client_key, size_t* client_key_size, uint8_t* iv, size_t iv_size) {

	iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
	psa_status_t psa_status;
	uint8_t *output = NULL;
	size_t output_size = 0U;
	size_t out_size = 0U;

	const psa_algorithm_t alg = PSA_ALG_CBC_NO_PADDING;
	psa_cipher_operation_t operation = PSA_CIPHER_OPERATION_INIT;

	memset(&operation, 0, sizeof(operation));
	// TODO: when moving to the vendor range, use the unwrapping key ID as is coming from the blob
	psa_status = psa_cipher_decrypt_setup(&operation, EL2GOIMPORTTFM_KEK_SK, alg);
	PSA_SUCCESS_OR_EXIT_MSG("psa_cipher_decrypt_setup failed: 0x%08x", psa_status);

	psa_status = psa_cipher_set_iv(&operation, iv, iv_size);
	PSA_SUCCESS_OR_EXIT_MSG("psa_cipher_set_iv failed: 0x%08x", psa_status);

	out_size = psa_cmd->keyincmd_size;
	output = malloc(out_size);

	psa_status = psa_cipher_operation(&operation, psa_cmd->keyincmd, psa_cmd->keyincmd_size, AES_CBC_BLOCK_SIZE, output, out_size, &output_size);
	PSA_SUCCESS_OR_EXIT_MSG("psa_cipher_operation failed: 0x%08x", psa_status);

    agent_status = nxp_iot_agent_unpad_iso7816d4(output, &output_size);
    AGENT_SUCCESS_OR_EXIT_MSG("nxp_iot_agent_unpad_iso7816d4 failed: 0x%08x", agent_status);

	*client_key_size = output_size;

	*client_key = malloc(*client_key_size);

	memcpy(*client_key, output, *client_key_size);

	// clean heap
	memset(output, 0, output_size);
exit:
	free(output);
	return agent_status;
}

psa_status_t psa_import_key_wrap(const psa_key_attributes_t *attributes,
	const uint8_t *data,
	size_t data_length,
	mbedtls_svc_key_id_t *key) {
	psa_status_t psa_status = PSA_ERROR_GENERIC_ERROR;
	uint8_t *client_key = NULL;
	size_t client_key_size = 0U;
	psa_cmd_t psa_cmd = { 0U };

	psa_cmd_init(&psa_cmd);

	if (data_length < 16 + sizeof(MAGIC)) {
        // TODO: in that case we perhaps should just let regular mbedtls import the key...
		IOT_AGENT_ERROR("Data length is too small to contain magic and signature");
		goto exit;
    }
    if (memcmp(MAGIC, data, sizeof(MAGIC)) != 0) {
        // TODO: in that case we perhaps should just let regular mbedtls import the key...
		IOT_AGENT_ERROR("Magic not found, this is not an EdgeLock 2GO keyblob");
		goto exit;
    }
	if (parse_psa_import_cmd(data, data_length, &psa_cmd) != IOT_AGENT_SUCCESS) {
		IOT_AGENT_ERROR("Error in parsing of agent");
		goto exit;
	}
	// TODO: when moving to the vendor range, use the unwrapping key ID as is coming from the blob
	if (verify_cmd_cmac(EL2GOIMPORT_AUTH_SK, data, data_length) != IOT_AGENT_SUCCESS) {
		IOT_AGENT_ERROR("Error in verification of CMAC");
		goto exit;
	}

	if (psa_cmd.wrapping_algorithm == WRAPPING_ALG_RFC3394) {
		if (unwrap_key(&psa_cmd, &client_key, &client_key_size) != IOT_AGENT_SUCCESS) {
			IOT_AGENT_ERROR("Error in unwrapping key");
			goto exit;
		}

		if (psa_get_key_id(&psa_cmd.attributes) == EL2GO_OEM_FW_DECRYPT_KEY) {
			psa_set_key_lifetime(&psa_cmd.attributes, PSA_KEY_LIFETIME_VOLATILE);
			psa_set_key_type(&psa_cmd.attributes, PSA_KEY_TYPE_AES);
			if (psa_cmd.attributes.core.bits >= (CMD_IN_KEY_OFFSET * 8U)) {
				psa_set_key_bits(&psa_cmd.attributes, psa_cmd.attributes.core.bits - (CMD_IN_KEY_OFFSET * 8U));
			}
			else {
				IOT_AGENT_ERROR("Error in key_bits");
				goto exit;
			}
		}
	}
	else if (psa_cmd.wrapping_algorithm == WRAPPING_ALG_AES_CBC) {
		if (decrypt_key(&psa_cmd, &client_key, &client_key_size, psa_cmd.iv, psa_cmd.iv_size) != IOT_AGENT_SUCCESS) {
			IOT_AGENT_ERROR("Error in decrypting key");
			goto exit;
		}
	}
	else if (psa_cmd.wrapping_algorithm == WRAPPING_ALG_NONE) {
		// this is the RKTH case
		// the persistence must be set to Volatile to allow injecting an key from vendor range using psa_import_key
		// (inside psa_import_key a Persistent key from Vendor range is not allowed)
		psa_set_key_lifetime(&psa_cmd.attributes, PSA_KEY_LIFETIME_VOLATILE);
		client_key = malloc(psa_cmd.keyincmd_size);
		client_key_size = psa_cmd.keyincmd_size;
		memcpy(client_key, psa_cmd.keyincmd, client_key_size);
	}
	else {
		IOT_AGENT_ERROR("Wrapping Algorithm not supported");
		goto exit;
	}

	psa_status = psa_import_key(&psa_cmd.attributes, client_key, client_key_size, key);

	// clean heap
	memset(client_key, 0, client_key_size);
exit:
	free(client_key);
	return psa_status;
}
