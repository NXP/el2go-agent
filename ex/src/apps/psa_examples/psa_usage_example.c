/*
 * Copyright 2021, 2023 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <psa/crypto.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
//#include <ex_sss_main_inc.h>


#define ASSERT( predicate )                                                   \
    do                                                                        \
    {                                                                         \
        if( ! ( predicate ) )                                                 \
        {                                                                     \
            printf( "\tassertion failed at %s:%d - '%s'\r\n",         \
                    __FILE__, __LINE__, #predicate);                  \
            goto exit;                                                        \
        }                                                                     \
    } while ( 0 )

#define ASSERT_STATUS( actual, expected )                                     \
    do                                                                        \
    {                                                                         \
        if( ( actual ) != ( expected ) )                                      \
        {                                                                     \
            printf( "\tassertion failed at %s:%d - "                  \
                    "actual:%d expected:%d\r\n", __FILE__, __LINE__,  \
                            (psa_status_t) actual, (psa_status_t) expected ); \
            goto exit;                                                        \
        }                                                                     \
    } while ( 0 )

static const uint8_t RSA_1024_KEY[] =
{
	// fill the RSA key with correct values
	0x30, 0x82,
};

static psa_status_t import_rsa_priv_key(const uint8_t *key, size_t key_len)
{
	psa_status_t status;
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t id;

	printf("Import an RSA private key...\t");
	fflush(stdout);

	/* Set key attributes */
	psa_set_key_usage_flags(&attributes, 0);
	psa_set_key_algorithm(&attributes, 0);
	psa_set_key_type(&attributes, PSA_KEY_TYPE_RSA_KEY_PAIR);
	psa_set_key_bits(&attributes, 1024);
	psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_PERSISTENT);
	psa_set_key_id(&attributes, 0x00888888);

	/* Import the key */
	status = psa_import_key(&attributes, key, key_len, &id);
	ASSERT_STATUS(status, PSA_SUCCESS);
	printf("Imported a key\n");

	/* Free the attributes */
	psa_reset_key_attributes(&attributes);

	/* Destroy the key */
	status = psa_destroy_key(id);
	ASSERT_STATUS(status, PSA_SUCCESS);

exit:
	return(status);
}

static const uint8_t EC_SECP_R1_256_KEY[] =
{
	0xd2, 0x30, 0xbd, 0xb1, 0xa7, 0x59, 0xe8, 0x09, 0x27, 0xac, 0xb2,
	0x03, 0x7a, 0x69, 0x11, 0x8a, 0x18, 0x76, 0x52, 0xb1, 0x1f, 0x40,
	0xe5, 0x81,	0x9a, 0x30,	0x43, 0xb0, 0x35, 0x4e, 0xab, 0xc5};

static psa_status_t import_ec_priv_key(const uint8_t *key, size_t key_len)
{
	psa_status_t status;
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t id;

	printf("Import an EC private key...\t");
	fflush(stdout);

	/* Set key attributes */
	psa_set_key_usage_flags(&attributes, 0);
	psa_set_key_algorithm(&attributes, 0);
	//psa_set_key_algorithm(&attributes, PSA_ALG_ECDSA_ANY);
	psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
	//psa_set_key_bits(&attributes, 256);
	psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_PERSISTENT);
	psa_set_key_id(&attributes, 0x00001111);

	/* Import the key */
	status = psa_import_key(&attributes, key, key_len, &id);
	ASSERT_STATUS(status, PSA_SUCCESS);
	printf("Imported a key\n");

	/* Free the attributes */
	psa_reset_key_attributes(&attributes);

	/* Destroy the key */
	status = psa_destroy_key(id);
	ASSERT_STATUS(status, PSA_SUCCESS);

exit:
	return(status);
}

static const uint8_t AES_KEY[] =
{
	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
	0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
};

static psa_status_t import_aes_key(const uint8_t *key, size_t key_len)
{
	psa_status_t status;
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t id;

	printf("Import an AES key...\t");
	fflush(stdout);

	/* Set key attributes */
	psa_set_key_usage_flags(&attributes, 0);
	psa_set_key_algorithm(&attributes, 0);
	psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
	psa_set_key_bits(&attributes, 128);
	psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_PERSISTENT);
	psa_set_key_id(&attributes, 0x00008888);

	/* Import the key */
	status = psa_import_key(&attributes, key, key_len, &id);
	ASSERT_STATUS(status, PSA_SUCCESS);
	printf("Imported a key\n");

	/* Free the attributes */
	psa_reset_key_attributes(&attributes);

	/* Destroy the key */
	status = psa_destroy_key(id);
	ASSERT_STATUS(status, PSA_SUCCESS);

exit:
	return(status);
}
static psa_status_t sign_verify()
{
	psa_status_t status;
	psa_key_id_t key = 0;
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_attributes_t readAttributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
	psa_set_key_algorithm(&attributes, PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_256));
	psa_set_key_id(&attributes, 0x00000088);
	psa_set_key_usage_flags(&attributes,
		PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH);
	psa_set_key_bits(&attributes, 256);
	psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_PERSISTENT);

	// Key Gen
	status = psa_generate_key(&attributes, &key);
	// If exist destroy and then generate
	if (status == PSA_ERROR_ALREADY_EXISTS)
	{
		status = psa_destroy_key(psa_get_key_id(&attributes));
		ASSERT_STATUS(status, PSA_SUCCESS);
		status = psa_generate_key(&attributes, &key);
		ASSERT_STATUS(status, PSA_SUCCESS);
	}

	// Get Attributes
	status = psa_get_key_attributes(key, &readAttributes);
	ASSERT_STATUS(status, PSA_SUCCESS);

	uint8_t input[PSA_SIGNATURE_MAX_SIZE];
	uint8_t signature[PSA_SIGNATURE_MAX_SIZE];
	size_t signature_length;
	size_t random_len = sizeof(input);

	status = psa_generate_random(input, random_len);
	ASSERT_STATUS(status, PSA_SUCCESS);

	printf("generated hash input: ");
	for (size_t i = 0; i < sizeof(input); i++) {
		printf("%x", input[i]);
		}
	printf("\n");

	// Sign Hash
	status = psa_sign_hash(key, PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_256),
		input,
		256,
		signature,
		PSA_SIGNATURE_MAX_SIZE,
		&signature_length);
	ASSERT_STATUS(status, PSA_SUCCESS);

	// Verify Hash
	status = psa_verify_hash(key, PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_256),
		input,
		256,
		signature,
		signature_length);
	ASSERT_STATUS(status, PSA_SUCCESS);

	// Destroy Key
	status = psa_destroy_key(key);
	ASSERT_STATUS(status, PSA_SUCCESS);

	/* Free the attributes */
	psa_reset_key_attributes(&attributes);
	psa_reset_key_attributes(&readAttributes);

exit:
	return(status);
}

static const uint8_t EC_SECP_R1_256_PUBLIC_KEY[] =
{
	0x04, 0x17, 0x43, 0x9D, 0xF6, 0xCA, 0x17, 0x9E, 0x72,
	0xB6, 0xA0, 0x65, 0x08, 0x8A, 0x7D, 0x60, 0xD2, 0x7E,
	0x0D, 0x83, 0x32, 0x67, 0xEC, 0xF5, 0xA3, 0x3C, 0x2A,
	0x5E, 0x48, 0x08, 0x35, 0xB8, 0xCA, 0xA3, 0xCF, 0x1B,
	0xAA, 0xDC, 0x45, 0x83, 0xF2, 0xBB, 0x88, 0x31, 0xDC,
	0x7A, 0x6A, 0x5C, 0xBE, 0x26, 0x20, 0xDF, 0xBB, 0xF7,
	0x67, 0x13, 0x4F, 0x34, 0xDA, 0xD6, 0xA8, 0x16, 0x96,
	0xAA, 0xD3
};

static psa_status_t import_ec_public_key(const uint8_t *key, size_t key_len)
{
	psa_status_t status;
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t id;

	printf("Import an EC public key...\t");
	fflush(stdout);

	/* Set key attributes */
	psa_set_key_usage_flags(&attributes, 0);
	psa_set_key_algorithm(&attributes, 0);
	//psa_set_key_algorithm(&attributes, PSA_ALG_ECDSA_ANY);
	psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
	//psa_set_key_bits(&attributes, 256);
	psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_PERSISTENT);
	psa_set_key_id(&attributes, 0x00001188);

	/* Import the key */
	status = psa_import_key(&attributes, key, key_len, &id);
	ASSERT_STATUS(status, PSA_SUCCESS);
	printf("Imported a key\n");

	/* Free the attributes */
	psa_reset_key_attributes(&attributes);

	/* Destroy the key */
	status = psa_destroy_key(id);
	ASSERT_STATUS(status, PSA_SUCCESS);

exit:
	return(status);
}

int main()
{
	ASSERT(psa_crypto_init() == PSA_SUCCESS);

	ASSERT(sign_verify() == PSA_SUCCESS);
	ASSERT(import_aes_key(AES_KEY, sizeof(AES_KEY)) == PSA_SUCCESS);
	ASSERT(import_rsa_priv_key(RSA_1024_KEY, sizeof(RSA_1024_KEY)) == PSA_SUCCESS);
	ASSERT(import_ec_priv_key(EC_SECP_R1_256_KEY, sizeof(EC_SECP_R1_256_KEY)) == PSA_SUCCESS);
	ASSERT(import_ec_public_key(EC_SECP_R1_256_PUBLIC_KEY, sizeof(EC_SECP_R1_256_PUBLIC_KEY)) == PSA_SUCCESS);

	printf("  Press Enter to exit this program.\n");
	fflush(stdout); getchar();

exit:
	return(0);
}


