/*
 * Copyright 2021,2023-2024 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */
#include "psa_init_utils.h"
#include "psa_crypto_its.h"
#include "nxp_iot_agent_macros.h"
#include "nxp_iot_agent_macros_psa.h"
#include "nxp_iot_agent_log.h"
#include <string.h>

#ifdef psa_import_key
#undef psa_import_key
#define psa_import_key psa_import_key
#endif

#define BUF_SIZE (1000)
#define MAX_KEY_SIZE (65) // NIST-P256 public key is 65 bytes
#define KEY_ID_SIZE (4)
#define MAX_KEY_TYPE_SIZE (5)
#define PERMITTED_ALG_SIZE (4)
#define KEY_USAGE_SIZE (4)

 /** @brief Get length of provided acsii input in bytes
 *
 */
iot_agent_status_t get_ascii_hex_len(const char* input, size_t *len) {
	iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
	if ((strlen(input) % 2) != 0) {
		agent_status = IOT_AGENT_FAILURE;
		goto exit;
	}
	*len = strlen(input) / 2;

exit:
	return agent_status;
}

/** @brief Convert hex to bin
*
*/
iot_agent_status_t ascii_hex_to_bin(char *str, size_t *len, uint8_t *buffer) {
	iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;

	if ((strlen(str) % 2) != 0) {
		agent_status = IOT_AGENT_FAILURE;
		goto exit;
	}

	*len = strlen(str) / 2;

	char *pos = str;
	for (size_t count = 0; count < *len; count++) {
		if (sscanf(pos, "%2hhx", &buffer[count]) < 1) {
			*len = 0;
			agent_status = IOT_AGENT_FAILURE;
			goto exit;
		}
		pos += 2;
	}

exit:
	return agent_status;
}

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

static psa_status_t import_key(const uint8_t *key, size_t key_len, psa_key_id_t id, psa_key_type_t psa_key_type, psa_algorithm_t psa_algorithm, psa_key_usage_t psa_key_usage)
{
	psa_status_t psa_status = PSA_SUCCESS;
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

	/* Set key attributes */
	psa_set_key_usage_flags(&attributes, psa_key_usage);
	psa_set_key_algorithm(&attributes, psa_algorithm);
	psa_set_key_type(&attributes, psa_key_type);
	psa_set_key_id(&attributes, id);
	// inside psa_import_key a Persistent key from Vendor range is not allowed,
	// so set the persistenceto volatile
	if ((PSA_KEY_ID_USER_MIN <= id) &&
		(id <= PSA_KEY_ID_USER_MAX)) {
	psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_PERSISTENT);
	} 
	else if ((PSA_KEY_ID_VENDOR_MIN <= id) &&
		(id <= PSA_KEY_ID_VENDOR_MAX)) {
		psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_VOLATILE);
	}

	/* Import the key */
	psa_status = psa_import_key(&attributes, key, key_len, &id);
	if (psa_status == PSA_ERROR_ALREADY_EXISTS) {
		psa_destroy_key(psa_get_key_id(&attributes));
		psa_status = psa_import_key(&attributes, key, key_len, &id);
	}
	if (psa_status != PSA_SUCCESS)
	{
		goto exit;
	}

	/* Free the attributes */
	psa_reset_key_attributes(&attributes);

exit:
	return psa_status;
}

iot_agent_status_t psa_init_utils_import_cmd(const char* cmd) {
	iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
	psa_status_t psa_status = PSA_SUCCESS;
	char key_id_str[BUF_SIZE] = { 0 };
	char key_type_str[BUF_SIZE] = { 0 };
	char key_value_str[BUF_SIZE] = { 0 };
	char key_permitted_alg_str[BUF_SIZE] = { 0 };
	char key_usage_str[BUF_SIZE] = { 0 };
	size_t in_len = 0;
	int found = 0;

	ASSERT_OR_EXIT_MSG(cmd != NULL, "Error in the input parameters");

	// Read line
	found = sscanf(cmd, "keydata %s %s %s %s %s", key_id_str, key_type_str, key_permitted_alg_str, key_usage_str, key_value_str);
	if (found <= 0) {
		//IOT_AGENT_DEBUG("discarding [%s]\n", cmd);
		agent_status = IOT_AGENT_SUCCESS;
		goto exit;
	}

	IOT_AGENT_DEBUG("Key ID: %s\r\n", key_id_str);
	IOT_AGENT_DEBUG("Key type: %s\r\n", key_type_str);
	IOT_AGENT_DEBUG("Key permitted algorithm: %s\r\n", key_permitted_alg_str);
	IOT_AGENT_DEBUG("Key usage: %s\r\n", key_usage_str);
	IOT_AGENT_DEBUG("Key Value: %s\r\n", key_value_str);

	// check keyId length
	agent_status = get_ascii_hex_len(key_id_str, &in_len);
	AGENT_SUCCESS_OR_EXIT_MSG("Error, wrong hex format %s\n", key_id_str);
	ASSERT_OR_EXIT_MSG(in_len == KEY_ID_SIZE, "Provided KEYID length error: %s\n", key_id_str);

	// check permitted alg length
	agent_status = get_ascii_hex_len(key_permitted_alg_str, &in_len);
	AGENT_SUCCESS_OR_EXIT_MSG("Error, wrong hex format %s\n", key_permitted_alg_str);
	ASSERT_OR_EXIT_MSG(in_len == PERMITTED_ALG_SIZE, "Provided PERMITTED_ALG_SIZE length error: %s\n", key_permitted_alg_str);

	// check key usage length
	agent_status = get_ascii_hex_len(key_usage_str, &in_len);
	AGENT_SUCCESS_OR_EXIT_MSG("Error, wrong hex format %s\n", key_usage_str);
	ASSERT_OR_EXIT_MSG(in_len == KEY_USAGE_SIZE, "Provided KEY_USAGE_SIZE length error: %s\n", key_usage_str);

	// check key type length
	agent_status = get_ascii_hex_len(key_type_str, &in_len);
	AGENT_SUCCESS_OR_EXIT_MSG("Error, wrong hex format %s\n", key_type_str);
	ASSERT_OR_EXIT_MSG(in_len <= MAX_KEY_TYPE_SIZE, "Provided KEY_TYPE length error: %s\n", key_type_str);

	// check Key Value
	agent_status = get_ascii_hex_len(key_value_str, &in_len);
	AGENT_SUCCESS_OR_EXIT_MSG("Error, wrong hex format %s\n", key_value_str);
	ASSERT_OR_EXIT_MSG(in_len <= MAX_KEY_SIZE, "Provided KEY_VALUE length error: %s\n", key_value_str);

	uint8_t key_id[KEY_ID_SIZE] = { 0U };
	size_t key_id_len = 0;
	uint8_t key_value[MAX_KEY_SIZE] = { 0U };
	size_t key_value_len = 0;

	uint8_t key_permitted_alg[PERMITTED_ALG_SIZE] = { 0U };
	size_t key_permitted_alg_len = 0;
	uint8_t key_usage[KEY_USAGE_SIZE] = { 0U };
	size_t key_usage_len = 0;

	agent_status = ascii_hex_to_bin(key_id_str, &key_id_len, key_id);
	AGENT_SUCCESS_OR_EXIT_MSG("invalid hexstr in [%s]\n", key_id_str);

	agent_status = ascii_hex_to_bin(key_value_str, &key_value_len, key_value);
	AGENT_SUCCESS_OR_EXIT_MSG("invalid hexstr in [%s]\n", key_value_str);

	agent_status = ascii_hex_to_bin(key_permitted_alg_str, &key_permitted_alg_len, key_permitted_alg);
	AGENT_SUCCESS_OR_EXIT_MSG("invalid hexstr in [%s]\n", key_permitted_alg_str);

	agent_status = ascii_hex_to_bin(key_usage_str, &key_usage_len, key_usage);
	AGENT_SUCCESS_OR_EXIT_MSG("invalid hexstr in [%s]\n", key_usage_str);

	// TODO: I was finishing here => check also outside the returend value in found to know if continue or not!!!

	// if key type EC private
	if (strcmp(key_type_str, "00") == 0) {
		psa_status = import_key(key_value, key_value_len, (psa_key_id_t)get_uint32_val(key_id),
			PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1), (psa_algorithm_t)get_uint32_val(key_permitted_alg), (psa_key_usage_t)get_uint32_val(key_usage));
		PSA_SUCCESS_OR_EXIT_MSG("key import failed, keyId is [%s], psa status code [%d]\n", key_id_str, psa_status);
		IOT_AGENT_INFO("key with keyId [%s] imported\n", key_id_str);
	}
	// if key type EC public
	else if (strcmp(key_type_str, "02") == 0) {
		psa_status = import_key(key_value, key_value_len, (psa_key_id_t)get_uint32_val(key_id),
			PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1), (psa_algorithm_t)get_uint32_val(key_permitted_alg), (psa_key_usage_t)get_uint32_val(key_usage));
		PSA_SUCCESS_OR_EXIT_MSG("key import failed, keyId is [%s], psa status code [%d]\n", key_id_str, psa_status);
		IOT_AGENT_INFO("key with keyId [%s] imported\n", key_id_str);
	}
	// if key type AES
	else if (strcmp(key_type_str, "01") == 0) {
		psa_status = import_key(key_value, key_value_len, (psa_key_id_t)get_uint32_val(key_id), PSA_KEY_TYPE_AES,
			(psa_algorithm_t)get_uint32_val(key_permitted_alg), (psa_key_usage_t)get_uint32_val(key_usage));
		PSA_SUCCESS_OR_EXIT_MSG("key import failed, keyId is [%s], psa status code [%d]\n", key_id_str, psa_status);
		IOT_AGENT_INFO("key with keyId [%s] imported\n", key_id_str);
	}
	// if key type UID
	else if (strcmp(key_type_str, "40") == 0) {
		// Note, this is not at all reflecting reality, real devices come with a UID in OTP, but for a simulation we have to put 
		// it somewhere. As all of the keys are in ITS, we also put the UID there.
		psa_storage_uid_t storage_id = get_uint32_val(key_id);
		psa_status = psa_its_set(storage_id, key_value_len, key_value, PSA_STORAGE_FLAG_NONE);
		PSA_SUCCESS_OR_EXIT_MSG("key import failed, keyId is [%s], psa status code [%d]\n", key_id_str, psa_status);
		IOT_AGENT_INFO("UID with keyId [%s] imported\n", key_id_str);
	}
	else {
		IOT_AGENT_WARN("keyType [%s] with keyId[%s] not supported\n", key_type_str, key_id_str);
	}
exit:
	return agent_status;
}