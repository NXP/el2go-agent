/* Copyright 2022-2023 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "iot_agent_claimcode_encrypt.h"
#include "nxp_iot_agent.h"

#if SSS_HAVE_MBEDTLS_ALT_PSA

 // TODO: remove that once the import_key_wrap hack is removed!
#undef psa_import_key

#include "nxp_iot_agent_macros.h"
#include "nxp_iot_agent_utils.h"

#include "psa/crypto.h"
#include "psa_crypto_its.h"

#define AES_CBC_BLOCK_SIZE  		16

// These are defined key properties from the S50 on RW610. We need to use the same properties 
// also on the simulator.
/*! @name KS0 - Status register */
/*! @{ */
#define CSSV2_KS0_KS0_KSIZE_MASK                 (0x1U)
#define CSSV2_KS0_KS0_KSIZE_SHIFT                (0U)
/*! KS0_KSIZE - Key size: 0-128, 1-256
 */

static iot_agent_status_t iot_agent_generate_claimcode_keypair(psa_key_id_t* key_id) {
    iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
	psa_status_t psa_status = PSA_SUCCESS;
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    ASSERT_OR_EXIT_MSG(key_id != NULL, "key_id is NULL");

	/* Set key attributes */
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);
	psa_set_key_algorithm(&attributes, PSA_ALG_ECDH);
	psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_CURVE_SECP_R1));
    psa_set_key_bits(&attributes, 256);
	psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_VOLATILE);
	// psa_set_key_id(&attributes, key_id);

    psa_status = psa_generate_key(&attributes, key_id);
    PSA_SUCCESS_OR_EXIT_MSG("psa_generate_key failed: 0x%08x", psa_status);
exit:
    return agent_status;
}

static iot_agent_status_t iot_agent_claimcode_ecdh(psa_key_id_t private_key_id, 
        const uint8_t* el2go_public_key, size_t el2go_public_key_size,
        uint8_t* shared_secret, size_t shared_secret_size, size_t* shared_secret_length) 
{
    iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
	psa_status_t psa_status = PSA_SUCCESS;

    psa_status = psa_raw_key_agreement(PSA_ALG_ECDH, private_key_id, 
            el2go_public_key, el2go_public_key_size, 
            shared_secret, shared_secret_size, shared_secret_length);
    PSA_SUCCESS_OR_EXIT_MSG("psa_raw_key_agreement failed: 0x%08x", psa_status);

exit:
    return agent_status;
}


static const uint8_t iot_agent_claimcode_derivation_data_enc[12] = "CC_ENC"; 
static const uint8_t iot_agent_claimcode_derivation_data_mac[12] = "CC_MAC"; 

// These don't make any sense on the simulator, we use the values we'd expect on the real
// implementation.
static const uint32_t key_properties_enc = 0x20001080; 
static const uint32_t key_properties_mac = 0x20200080;

static inline void write_uint32_to_dd(uint8_t* pos, uint32_t data) {
    pos[0] = ((data) >> 24) & 0xFF;
    pos[1] = ((data) >> 16) & 0xFF;
    pos[2] = ((data) >>  8) & 0xFF;
    pos[3] = ((data) >>  0) & 0xFF;
}

static iot_agent_status_t iot_agent_claimcode_ckdf(const uint8_t* input_key, size_t input_key_size, 
        const uint8_t* derivation_data, size_t derivation_data_size, uint32_t key_properties,
        uint8_t* output, size_t output_size, size_t* output_length) 
{
    iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;

    int ret = 0;
    uint32_t counter = 1;
    mbedtls_cipher_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));


    ASSERT_OR_EXIT_MSG(input_key != NULL, "input_key is NULL");
    ASSERT_OR_EXIT_MSG(input_key_size == 32, "input key size is != 32");
    ASSERT_OR_EXIT_MSG(derivation_data != NULL, "derivation_data is NULL");
    ASSERT_OR_EXIT_MSG(derivation_data_size == 12, "derivation_data size != 12");
    ASSERT_OR_EXIT_MSG(output != NULL, "output is NULL");
    ASSERT_OR_EXIT_MSG(output_size == 32, "output_size != 32");

    *output_length = (1 + ((key_properties & CSSV2_KS0_KS0_KSIZE_MASK) >> CSSV2_KS0_KS0_KSIZE_SHIFT)) * AES_CBC_BLOCK_SIZE;

    //KDF in counter mode implementation as described in Section 5.1
    //of NIST SP 800-108, Recommendation for Key Derivation Using Pseudorandom Functions
    // Derivation data[191:0](sic!) = software_derivation_data[95:0] || 64'h0 || requested_
    // properties[31:0 || length[31:0] || counter[31:0]

    uint8_t dd[32] = { 0 };
    memcpy(&dd[0], derivation_data, derivation_data_size);
    memset(&dd[12], 0, 8);
    write_uint32_to_dd(&dd[20], key_properties);
    write_uint32_to_dd(&dd[24], (*output_length) * 8); // expected in bits!
    write_uint32_to_dd(&dd[28], counter);

    mbedtls_cipher_type_t mbedtls_cipher_type = MBEDTLS_CIPHER_AES_256_ECB;
    const mbedtls_cipher_info_t *cipher_info = mbedtls_cipher_info_from_type(mbedtls_cipher_type);

    do {
    	mbedtls_cipher_init(&ctx);

    	ret = mbedtls_cipher_setup(&ctx, cipher_info);
        ASSERT_OR_EXIT_MSG(ret == 0, "mbedtls_cipher_setup failed: 0x%08x", ret);

        ret = mbedtls_cipher_cmac_starts(&ctx, input_key, input_key_size * 8);
        ASSERT_OR_EXIT_MSG(ret == 0, "mbedtls_cipher_cmac_starts failed: 0x%08x", ret);

        ret = mbedtls_cipher_cmac_update(&ctx, dd, sizeof(dd));
        ASSERT_OR_EXIT_MSG(ret == 0, "mbedtls_cipher_cmac_update failed: 0x%08x", ret);

        ret = mbedtls_cipher_cmac_finish(&ctx, output);
        ASSERT_OR_EXIT_MSG(ret == 0, "mbedtls_cipher_cmac_finish failed: 0x%08x", ret);

        mbedtls_cipher_free( &ctx );

        write_uint32_to_dd(&dd[28], ++counter);
        output += 16;
    } while (counter * AES_CBC_BLOCK_SIZE <= *output_length);

exit:
    if (ctx.cipher_ctx != NULL) {
    	mbedtls_cipher_free( &ctx );
    }

    return agent_status;
}


static iot_agent_status_t iot_agent_derive_enc_key(psa_key_id_t private_key_id, 
        const uint8_t* el2go_public_key, size_t el2go_public_key_size,
        psa_key_id_t* derived_key_id) 
{
    // TODO: Mbedtls does not support CKDF. I hope, we will get an abstraction on the psa interface
    // for the ckdf of S50 with opaque keys from the cl-team.
    // Here, for the simulator, there is no other way than to get the raw shared secret and manually
    // perform the CKDF using mbedtls primitives :-(.

    iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
	psa_status_t psa_status = PSA_SUCCESS;
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

    ASSERT_OR_EXIT_MSG(derived_key_id != NULL, "derived_key_id is NULL");

    uint8_t shared_secret[256] = { 0 };
    size_t shared_secret_length = 0;
    agent_status = iot_agent_claimcode_ecdh(private_key_id, el2go_public_key, el2go_public_key_size, 
            shared_secret, sizeof(shared_secret), &shared_secret_length);
    AGENT_SUCCESS_OR_EXIT_MSG("iot_agent_claimcode_ecdh failed: 0x%08x", agent_status);

    uint8_t key[32] = { 0 };
    size_t key_size = sizeof(key);
    size_t key_length = 0;

    agent_status = iot_agent_claimcode_ckdf(shared_secret, shared_secret_length, 
            iot_agent_claimcode_derivation_data_enc, sizeof(iot_agent_claimcode_derivation_data_enc),
            key_properties_enc, key, key_size, &key_length);

	/* Set key attributes */
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_ENCRYPT);
	psa_set_key_algorithm(&attributes, PSA_ALG_CBC_NO_PADDING);
	psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attributes, key_length * 8);
	psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_VOLATILE);

    psa_status = psa_import_key(&attributes, key, key_length, derived_key_id);
    PSA_SUCCESS_OR_EXIT_MSG("psa_import_key failed: 0x%08x", psa_status);
exit:
    return agent_status;
}

static iot_agent_status_t iot_agent_derive_mac_key(psa_key_id_t private_key_id, 
        const uint8_t* el2go_public_key, size_t el2go_public_key_size,
        psa_key_id_t* derived_key_id) 
{
    // TODO: Mbedtls does not support CKDF. I hope, we will get an abstraction on the psa interface
    // for the ckdf of S50 with opaque keys from the cl-team.
    // Here, for the simulator, there is no other way than to get the raw shared secret and manually
    // perform the CKDF using mbedtls primitives :-(.

    iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
	psa_status_t psa_status = PSA_SUCCESS;
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

    ASSERT_OR_EXIT_MSG(derived_key_id != NULL, "derived_key_id is NULL");

    uint8_t shared_secret[256] = { 0 };
    size_t shared_secret_length = 0;
    agent_status = iot_agent_claimcode_ecdh(private_key_id, el2go_public_key, el2go_public_key_size, 
        shared_secret, sizeof(shared_secret), &shared_secret_length);
    AGENT_SUCCESS_OR_EXIT_MSG("iot_agent_claimcode_ecdh failed: 0x%08x", agent_status);

    uint8_t key[32] = { 0 };
    size_t key_size = sizeof(key);
    size_t key_length = 0;

    agent_status = iot_agent_claimcode_ckdf(shared_secret, shared_secret_length, 
            iot_agent_claimcode_derivation_data_mac, sizeof(iot_agent_claimcode_derivation_data_mac),
            key_properties_mac, key, key_size, &key_length);

	/* Set key attributes */
    // TODO: this version of mbedtls does not support cmac on PSA interface, so we need to export 
    // the key and then manually do cmac with mbedtls crypto primitives. This implies that the key
    // has to be allowed to be exported...
    // We actually would rather want somthing like this:
    // psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_MESSAGE);
	// psa_set_key_algorithm(&attributes, PSA_ALG_CMAC);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_EXPORT);
	psa_set_key_algorithm(&attributes, PSA_ALG_CMAC);
    
	psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attributes, key_length * 8);
    psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_VOLATILE);

    psa_status = psa_import_key(&attributes, key, key_length, derived_key_id);
    PSA_SUCCESS_OR_EXIT_MSG("psa_import_key failed: 0x%08x", psa_status);
exit:
    return agent_status;
}

static iot_agent_status_t iot_agent_encrypt_string(const char* str, psa_key_id_t enc_key_id, 
        uint8_t* iv, uint8_t* output, size_t output_size, size_t* output_len)
{
    iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
    psa_status_t psa_status = PSA_SUCCESS;

    // This does not include the terminating 0x00 character. The terminating 0x00 is NOT part of the
    // plaintext!
    size_t len = strlen(str);

    // Apply 7816 padding:
    uint8_t plaintext[512] = { 0 };
    size_t plaintext_len = 0;
    memcpy(plaintext, str, len);
    agent_status = iot_agent_pad_iso7816d4(plaintext, sizeof(plaintext), len, 
            AES_CBC_BLOCK_SIZE, &plaintext_len);
    AGENT_SUCCESS_OR_EXIT_MSG("iot_agent_pad_iso7816d4 failed: 0x%08x", agent_status)

	const psa_algorithm_t alg = PSA_ALG_CBC_NO_PADDING;
	psa_cipher_operation_t operation = PSA_CIPHER_OPERATION_INIT;

	psa_status = psa_cipher_encrypt_setup(&operation, enc_key_id, alg);
	PSA_SUCCESS_OR_EXIT_MSG("psa_cipher_decrypt_setup failed: 0x%08x", psa_status);

	psa_status = psa_cipher_set_iv(&operation, iv, AES_CBC_BLOCK_SIZE);
	PSA_SUCCESS_OR_EXIT_MSG("psa_cipher_set_iv failed: 0x%08x", psa_status);

    size_t block_len;
    for (size_t offset = 0; offset < plaintext_len; offset += AES_CBC_BLOCK_SIZE) {
		psa_status = psa_cipher_update(&operation, plaintext + offset, AES_CBC_BLOCK_SIZE,
                output + offset, output_size, &block_len);
		PSA_SUCCESS_OR_EXIT_MSG("psa_cipher_update failed: 0x%08x", psa_status);
    }

	psa_status = psa_cipher_finish(&operation, output + plaintext_len,
		output_size - *output_len, &block_len);
	PSA_SUCCESS_OR_EXIT_MSG("psa_cipher_finish failed: 0x%08x", psa_status);

    *output_len = plaintext_len;


    // TODO: this would be much easier but is not yet there in mbedtls version we have
    // psa_status = psa_cipher_encrypt(enc_key_id, PSA_ALG_CBC_NO_PADDING, plaintext, plaintext_len, 
            // output, sizeof(output), output_len);
    // PSA_SUCCESS_OR_EXIT_MSG("psa_cipher_encrypt failed: 0x%08x", psa_status);
    //
    
exit:
    return agent_status;
}


static iot_agent_status_t iot_agent_claimcode_calculate_cmac(mbedtls_svc_key_id_t key_id, 
        const uint8_t* data, size_t len, uint8_t* calculated_cmac) {

	// As mbedtls 3 is not yet available, fall back to export + pure mbedtls cmac:
	iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
	const mbedtls_cipher_info_t *cipher_info;
	uint8_t cmac_key[32] = { 0U };
	size_t cmac_key_length = 0U;

	psa_status_t psa_status = psa_export_key(key_id, &cmac_key[0], sizeof(cmac_key), &cmac_key_length);
	PSA_SUCCESS_OR_EXIT_MSG("psa_export_key failed: 0x%08x", psa_status);
	if (cmac_key_length == 0x10) {
		cipher_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_ECB);
	} else if (cmac_key_length == 0x20) {
		cipher_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_ECB);
	}
	else {
		EXIT_STATUS_MSG(IOT_AGENT_FAILURE, "Invalid key size: 0x%08x bytes", cmac_key_length);
	}

	ASSERT_OR_EXIT_MSG(mbedtls_cipher_cmac(cipher_info, cmac_key, cmac_key_length * 8,
		data, len, calculated_cmac) == 0, "Error in CMAC execution");
exit:
	return agent_status;
}

iot_agent_status_t iot_agent_claimcode_encrypt(const char *claimcode, 
        const uint8_t* el2go_public_key, size_t el2go_public_key_size,
        uint8_t *claimcode_blob, size_t* claimcode_blob_len)
{
    psa_status_t psa_status = PSA_SUCCESS;
    iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
    psa_key_id_t keypair_key_id = 0;
    psa_key_id_t enc_key_id = 0;
    psa_key_id_t mac_key_id = 0;

    psa_status = psa_crypto_init();
    PSA_SUCCESS_OR_EXIT_MSG("psa_crypto_init failed: 0x%08x", psa_status);

    // Generate a keypair for the device (NXP_DIE_EL2GOCLAIMCODE_KP).
    agent_status = iot_agent_generate_claimcode_keypair(&keypair_key_id);
    AGENT_SUCCESS_OR_EXIT_MSG("iot_agent_generate_claimcode_keypair failed: 0x%08x", agent_status);
    
    // Use the device keypair plus the static public key from EdgeLock 2GO to calculate a shared
    // secret and use that shared secret for derivation of keys...

    // ...for encryption
    agent_status = iot_agent_derive_enc_key(keypair_key_id, 
            el2go_public_key, el2go_public_key_size, &enc_key_id);
    AGENT_SUCCESS_OR_EXIT_MSG("iot_agent_derive_enc_key failed: 0x%08x", agent_status);

    // ...for message authentication
    agent_status = iot_agent_derive_mac_key(keypair_key_id, 
            el2go_public_key, el2go_public_key_size, &mac_key_id);
    AGENT_SUCCESS_OR_EXIT_MSG("iot_agent_derive_mac_key failed: 0x%08x", agent_status);

    // We have all the keys, prepare the claimcode blob.

    uint8_t* pos = claimcode_blob;
    uint8_t* end = claimcode_blob + *claimcode_blob_len;

    *pos++ = 0x41;
    pos++; // +1 for skipping one length byte.
    size_t remaining_space = end - pos;
    size_t uid_len = remaining_space;
    agent_status = iot_agent_utils_get_device_id(pos, &uid_len);
    AGENT_SUCCESS_OR_EXIT_MSG("iot_agent_utils_get_device_id failed: 0x%08x", agent_status);
    ASSERT_OR_EXIT_MSG(uid_len < 0x80, "uid_len (0x%08x) is >= 0x80", uid_len);
    pos--; // Go back to the length byte that was skipped before.
    *pos++ = uid_len & 0x7F;
    pos += uid_len;

    *pos++ = 0x42;
    pos++; // +1 for skipping one length byte.
    remaining_space = end - pos;
    size_t public_key_len = 0;
    psa_status = psa_export_public_key(keypair_key_id, pos, remaining_space, &public_key_len);
	PSA_SUCCESS_OR_EXIT_MSG("psa_export_public_key failed: 0x%08x", psa_status);
    ASSERT_OR_EXIT_MSG(public_key_len < 0x80, "public_key_len (0x%08x) is >= 0x80", public_key_len);
    pos--; // Go back to the length byte that was skipped before.
    *pos++ = public_key_len & 0x7F;
    pos += public_key_len;

    *pos++ = 0x43;
    *pos++ = 4;
    *pos++ = (key_properties_enc >> 24) & 0xFF;
    *pos++ = (key_properties_enc >> 16) & 0xFF;
    *pos++ = (key_properties_enc >> 8) & 0xFF;
    *pos++ = (key_properties_enc) & 0xFF;

    *pos++ = 0x44;
    *pos++ = 4;
    *pos++ = (key_properties_mac >> 24) & 0xFF;
    *pos++ = (key_properties_mac >> 16) & 0xFF;
    *pos++ = (key_properties_mac >> 8) & 0xFF;
    *pos++ = (key_properties_mac) & 0xFF;

    *pos++ = 0x45;
    *pos++ = AES_CBC_BLOCK_SIZE;
    uint8_t* iv = pos;
    psa_status = psa_generate_random(iv, AES_CBC_BLOCK_SIZE);
	PSA_SUCCESS_OR_EXIT_MSG("psa_generate_random failed: 0x%08x", psa_status);
    pos += AES_CBC_BLOCK_SIZE;

    *pos++ = 0x46;
    pos++; // +1 for skipping one length byte.
    remaining_space = end - pos;
    size_t claimcode_enc_len = 0;
    agent_status = iot_agent_encrypt_string(claimcode, enc_key_id, iv, pos, 
            remaining_space, &claimcode_enc_len);
    AGENT_SUCCESS_OR_EXIT_MSG("iot_agent_encrypt_string failed: 0x%08x", agent_status);
    ASSERT_OR_EXIT_MSG(claimcode_enc_len < 0x80, "claimcode_enc_len (0x%08x) is >= 0x80", claimcode_enc_len);
    pos--; // Go back to the length byte that was skipped before.
    *pos++ = claimcode_enc_len & 0x7F;
    pos += claimcode_enc_len;

    *pos++ = 0x5e;
    *pos++ = AES_CBC_BLOCK_SIZE;
    agent_status = iot_agent_claimcode_calculate_cmac(mac_key_id, claimcode_blob, 
            pos - claimcode_blob, pos);
    AGENT_SUCCESS_OR_EXIT_MSG("iot_agent_claimcode_calculate_cmac failed: 0x%08x", agent_status);
    pos += AES_CBC_BLOCK_SIZE;

    *claimcode_blob_len = pos - claimcode_blob;

exit:
    return agent_status;
}

iot_agent_status_t iot_agent_claimcode_encrypt_and_import(char *claimcode, 
        const uint8_t* el2go_public_key, size_t el2go_public_key_size)
{
    iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
    psa_status_t psa_status = PSA_SUCCESS;

    uint8_t claimcode_blob[512] = {0};
    size_t claimcode_blob_len = sizeof(claimcode_blob);

    // Check if object exists.
    struct psa_storage_info_t storage_info = { 0 };
    psa_status = psa_its_get_info(CLAIMCODE_OBJ_ID, &storage_info);
    if (psa_status == PSA_SUCCESS) {
        psa_status = psa_its_remove(CLAIMCODE_OBJ_ID);
        ASSERT_OR_EXIT_MSG(psa_status == PSA_SUCCESS,
            "Error in destroying claim code.");
    }
    else {
        ASSERT_OR_EXIT_MSG(psa_status == PSA_ERROR_DOES_NOT_EXIST,
            "psa_its_get_info for claimcode failed: 0x%08x", psa_status);
    }

    agent_status = iot_agent_claimcode_encrypt(claimcode, el2go_public_key, el2go_public_key_size, 
                                &claimcode_blob[0], &claimcode_blob_len);
    AGENT_SUCCESS_OR_EXIT_MSG("iot_agent_claimcode_encrypt failed: 0x%08x", agent_status);

    psa_status = psa_its_set(CLAIMCODE_OBJ_ID, claimcode_blob_len, claimcode_blob, PSA_STORAGE_FLAG_NONE);
    PSA_SUCCESS_OR_EXIT_MSG("import of claimcode failed: 0x%08x", psa_status);
    IOT_AGENT_INFO("Claimcode imported into psa storage with object id 0x%08x", CLAIMCODE_OBJ_ID);

exit:
    return agent_status;
}

#endif // SSS_HAVE_MBEDTLS_ALT_PSA
