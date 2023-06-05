/*
 * Copyright 2021 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */
#include <psa/crypto.h>
#include <mbedtls/platform.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/error.h>
#include <mbedtls/pk.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/debug.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "nxp_iot_agent_macros.h"
#include "nxp_iot_agent_log.h"
#include "nxp_iot_agent_status.h"
#include "sss_x86_mbedtls_config.h"
#include "psa_crypto_wrapper.h"

static const mbedtls_ecp_group_id supported_curves[] = {MBEDTLS_ECP_DP_SECP192R1,
    MBEDTLS_ECP_DP_SECP224R1,
    MBEDTLS_ECP_DP_SECP256R1,
    MBEDTLS_ECP_DP_SECP384R1,
    MBEDTLS_ECP_DP_SECP521R1,
    MBEDTLS_ECP_DP_NONE};

static const uint8_t client_cert[] = {
	0x30, 0x82, 0x01, 0xB4, 0x30, 0x82, 0x01, 0x59, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x04,
	0x00, 0x50, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x51, 0x51, 0x51, 0x00, 0xCC,
	0x00, 0x00, 0x00, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02, 0x30,
	0x56, 0x31, 0x0C, 0x30, 0x0A, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x0C, 0x03, 0x4E, 0x58, 0x50, 0x31,
	0x17, 0x30, 0x15, 0x06, 0x03, 0x55, 0x04, 0x0B, 0x0C, 0x0E, 0x50, 0x6C, 0x75, 0x67, 0x20, 0x61,
	0x6E, 0x64, 0x20, 0x54, 0x72, 0x75, 0x73, 0x74, 0x31, 0x2D, 0x30, 0x2B, 0x06, 0x03, 0x55, 0x04,
	0x03, 0x0C, 0x24, 0x4E, 0x58, 0x50, 0x20, 0x49, 0x6E, 0x74, 0x65, 0x72, 0x6D, 0x65, 0x64, 0x69,
	0x61, 0x74, 0x65, 0x2D, 0x43, 0x6F, 0x6E, 0x6E, 0x65, 0x63, 0x74, 0x69, 0x76, 0x69, 0x74, 0x79,
	0x43, 0x41, 0x76, 0x44, 0x65, 0x6D, 0x6F, 0x30, 0x1E, 0x17, 0x0D, 0x32, 0x30, 0x30, 0x39, 0x33,
	0x30, 0x31, 0x35, 0x31, 0x39, 0x35, 0x36, 0x5A, 0x17, 0x0D, 0x33, 0x32, 0x30, 0x39, 0x33, 0x30,
	0x31, 0x35, 0x31, 0x39, 0x35, 0x36, 0x5A, 0x30, 0x4B, 0x31, 0x49, 0x30, 0x47, 0x06, 0x03, 0x55,
	0x04, 0x03, 0x0C, 0x40, 0x64, 0x79, 0x6E, 0x61, 0x6D, 0x69, 0x63, 0x74, 0x65, 0x73, 0x74, 0x2D,
	0x30, 0x34, 0x30, 0x30, 0x35, 0x30, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
	0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x35, 0x31, 0x35, 0x31, 0x35, 0x31, 0x30, 0x30,
	0x43, 0x43, 0x30, 0x30, 0x2D, 0x4B, 0x45, 0x59, 0x5F, 0x43, 0x45, 0x52, 0x54, 0x5F, 0x49, 0x4F,
	0x54, 0x48, 0x55, 0x42, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02,
	0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x83,
	0x45, 0x0B, 0xA5, 0x53, 0x3E, 0x23, 0x6E, 0xF3, 0x3A, 0xFE, 0xF5, 0x3F, 0xFA, 0xF8, 0x65, 0x67,
	0x64, 0x11, 0x7B, 0xE0, 0x6B, 0xB7, 0x17, 0x57, 0xAE, 0x56, 0x8F, 0xE3, 0x84, 0xDC, 0x2C, 0x71,
	0x35, 0x21, 0xB3, 0x5E, 0x13, 0xB1, 0x01, 0x5D, 0x08, 0xFD, 0xE0, 0xE8, 0x84, 0x5B, 0x2C, 0x13,
	0xB7, 0x87, 0xAB, 0x04, 0x18, 0xAF, 0x3B, 0xA1, 0xFC, 0x86, 0xAB, 0x71, 0x4C, 0xF1, 0xD6, 0xA3,
	0x10, 0x30, 0x0E, 0x30, 0x0C, 0x06, 0x03, 0x55, 0x1D, 0x13, 0x01, 0x01, 0xFF, 0x04, 0x02, 0x30,
	0x00, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02, 0x03, 0x49, 0x00,
	0x30, 0x46, 0x02, 0x21, 0x00, 0xF3, 0xF5, 0x04, 0x7F, 0x00, 0xFB, 0x86, 0xC5, 0x2B, 0x69, 0x2D,
	0xBA, 0xB2, 0xD3, 0x69, 0x7A, 0xFB, 0x8A, 0x4A, 0x1E, 0xA9, 0x2B, 0xF3, 0x62, 0xCA, 0xCA, 0xEF,
	0x65, 0xDC, 0x93, 0xD5, 0x98, 0x02, 0x21, 0x00, 0xCD, 0x75, 0xB0, 0xF6, 0x93, 0x0C, 0xF8, 0xD1,
	0x4A, 0xA0, 0xE4, 0x43, 0x20, 0xCB, 0xB1, 0x7F, 0x78, 0x9B, 0x3C, 0x36, 0xE0, 0x8E, 0xAC, 0x7B,
	0xE8, 0x7D, 0xC8, 0xDF, 0xA8, 0xAA, 0x77, 0x47
};

#ifdef MBEDTLS_USE_PSA_CRYPTO
/* the command was generated using the iothub-device-link-commons library with following inputs:
 * - key ID: 0x00000A00
 * - key algorithm: 0x060006FF (PSA_ALG_ECDSA(PSA_ALG_SHA_ANY))
 * - usage: 0x00001000 (PSA_KEY_USAGE_SIGN_HASH)
 * - type: 0x7112 (PSA_KEY_ECC_NISTP)
 * - Bits: 256
 * - magic: 9E81050C6AA2643D369E49
 * - Wrapping key ID: 0xF0000040
 * - Wrapping algorithm: 00000001 (RFC3394)
 * - Wrapping key: 9FA763FBD2085E95EF48163D6C5713EAF9B83BC0FCF175D939EB28523B5CA7FD
 * - MAC Key ID: 0xF0000050
 * - MAC Key: 169ACCDF144A66A742E66639037A67702CF3C521003F43CF44CFA1FCC84B1BD0
 * - RFC 3394 default IV: A6A6A6A6A6A6A6A6
 * - S50 Properties: 00020000 (UECSG)
 */
static const uint8_t psa_import_command[] = {
	0x10, 0x04, 0x00, 0x00, 0x0A, 0x00, 0x11, 0x04, 0x06, 0x00, 0x06, 0xFF, 0x12, 0x04, 0x00, 0x00,
	0x10, 0x00, 0x13, 0x02, 0x71, 0x12, 0x14, 0x04, 0x00, 0x00, 0x01, 0x00, 0x15, 0x0B, 0x2D, 0xC1,
	0x15, 0xCD, 0x1E, 0x8C, 0x8C, 0xB4, 0xB4, 0xE4, 0xCA, 0x20, 0x04, 0xF0, 0x00, 0x00, 0x40, 0x21,
	0x04, 0x00, 0x00, 0x00, 0x01, 0x23, 0x04, 0xF0, 0x00, 0x00, 0x50, 0x30, 0x38, 0x8C, 0xAD, 0x4B,
	0x9D, 0xAA, 0x0C, 0x0C, 0xAC, 0x52, 0xFE, 0xFF, 0xEC, 0x5B, 0xA0, 0x34, 0x8C, 0x64, 0xE3, 0xE8,
	0x72, 0xF7, 0xE0, 0x9B, 0xD0, 0x4A, 0x5D, 0xE0, 0xD2, 0x3D, 0xAA, 0x69, 0x7E, 0x25, 0x22, 0x2B,
	0x4F, 0x69, 0x5B, 0x07, 0x34, 0xE6, 0x82, 0xC8, 0xEB, 0xCA, 0x80, 0x9D, 0x7B, 0xA6, 0x88, 0xBE,
	0x71, 0x03, 0xFA, 0x3B, 0x97, 0xF0, 0x10, 0xCF, 0x93, 0xBE, 0x65, 0xC2, 0xE9, 0xFC, 0xD9, 0x1D,
	0x8A, 0x93, 0x8F, 0x88, 0x18, 0xBF, 0x24 };
#else
static const uint8_t client_key[] = {
	0x30, 0x81, 0x93, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02,
	0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x04, 0x79, 0x30, 0x77, 0x02,
	0x01, 0x01, 0x04, 0x20, 0x72, 0xAB, 0xA2, 0x4E, 0x48, 0x11, 0x2F, 0xAE, 0xDC, 0xAB, 0xF6, 0x1B,
	0x88, 0x0B, 0x41, 0x10, 0x95, 0xB4, 0x8C, 0xF0, 0xE5, 0x81, 0xA3, 0x65, 0x35, 0x83, 0x8E, 0x58,
	0x0A, 0x25, 0xC6, 0x24, 0xA0, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07,
	0xA1, 0x44, 0x03, 0x42, 0x00, 0x04, 0x83, 0x45, 0x0B, 0xA5, 0x53, 0x3E, 0x23, 0x6E, 0xF3, 0x3A,
	0xFE, 0xF5, 0x3F, 0xFA, 0xF8, 0x65, 0x67, 0x64, 0x11, 0x7B, 0xE0, 0x6B, 0xB7, 0x17, 0x57, 0xAE,
	0x56, 0x8F, 0xE3, 0x84, 0xDC, 0x2C, 0x71, 0x35, 0x21, 0xB3, 0x5E, 0x13, 0xB1, 0x01, 0x5D, 0x08,
	0xFD, 0xE0, 0xE8, 0x84, 0x5B, 0x2C, 0x13, 0xB7, 0x87, 0xAB, 0x04, 0x18, 0xAF, 0x3B, 0xA1, 0xFC,
	0x86, 0xAB, 0x71, 0x4C, 0xF1, 0xD6
};
#endif

static void my_debug(void *ctx, int level, const char *file, int line, const char *str)
{
    ((void)level);

    mbedtls_fprintf((FILE *)ctx, "%s:%04d: %s", file, line, str);
    fflush((FILE *)ctx);
}


/** @brief This function executes a TLS connection to the server.
 * 
 * It uses the PSA in case the MBEDTLS_USE_PSA_CRYPTO is defined in the MBED TLS configuration file,
 * otherwise the "normal" MBED TLS key parsing function will be used.
 *
 */
iot_agent_status_t mbedtls_client_connect()
{
	iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
	int ret = 0;
	mbedtls_ssl_context ssl = { 0U };
	mbedtls_ssl_config conf = { 0U };
	// this is the Deterministic random number generator
	mbedtls_ctr_drbg_context ctr_drbg = { 0U };
	mbedtls_pk_context pkey = { 0U };
	mbedtls_net_context server_fd = { 0U };
	mbedtls_entropy_context entropy = { 0U };
	mbedtls_x509_crt client_cert_x509 = { 0U };
#ifdef MBEDTLS_USE_PSA_CRYPTO
	psa_key_id_t key_id = 0U;
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_status_t psa_status;
#endif
	const char *pers = "test_mbedtls_client_psa";
	const char hostname[] = "127.0.0.1";
	int port = 7060;
	unsigned char max_fragment_len = MBEDTLS_SSL_MAX_FRAG_LEN_NONE;

	mbedtls_ssl_init(&ssl);
	mbedtls_ssl_config_init(&conf);
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_pk_init(&pkey);
	mbedtls_net_init(&server_fd);

	mbedtls_ssl_conf_dbg(&conf, my_debug, stdout);
	mbedtls_debug_set_threshold(5);

	mbedtls_entropy_init(&entropy);
	ASSERT_OR_EXIT_MSG(mbedtls_ctr_drbg_seed(
		&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers)) == 0,
		"Error in setting the DRBG seed");

	char port_str[32] = { 0 };
	snprintf(port_str, sizeof(port_str), "%d", port);

	ASSERT_OR_EXIT_MSG(mbedtls_net_connect(&server_fd, hostname, port_str, MBEDTLS_NET_PROTO_TCP) == 0,
		"Error in mbedtls_net_connect");

    mbedtls_net_set_block(&server_fd);

	ASSERT_OR_EXIT_MSG(mbedtls_ssl_config_defaults(
		&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT) == 0,
		"Error in mbedtls default configuration");

    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);

    if (MBEDTLS_SSL_MAX_CONTENT_LEN < 4096) {
        max_fragment_len = MBEDTLS_SSL_MAX_FRAG_LEN_2048;
    }
    else if (MBEDTLS_SSL_MAX_CONTENT_LEN < 16 * 1024) {
        max_fragment_len = MBEDTLS_SSL_MAX_FRAG_LEN_4096;
    }

    if (max_fragment_len != MBEDTLS_SSL_MAX_FRAG_LEN_NONE) {
		ASSERT_OR_EXIT_MSG(mbedtls_ssl_conf_max_frag_len(&conf, max_fragment_len) == 0,
			"Error in the configuration of maximum segmentation length");
    }

    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

	ASSERT_OR_EXIT_MSG(mbedtls_x509_crt_parse_der(&client_cert_x509, client_cert, sizeof(client_cert)) == 0,
		"Error in parsing of client certificate");

#ifdef MBEDTLS_USE_PSA_CRYPTO
	ASSERT_OR_EXIT_MSG(psa_crypto_init() == PSA_SUCCESS,
		"Error in PSA initialization");

	psa_status = psa_import_key_wrap(&attributes, psa_import_command, sizeof(psa_import_command), &key_id);
	if (psa_status == PSA_ERROR_ALREADY_EXISTS) {
		// delete the key and re-import it if already exist
		ASSERT_OR_EXIT_MSG(psa_destroy_key(psa_get_key_id(&attributes)) == PSA_SUCCESS,
			"Error in destroying the key object");
		ASSERT_OR_EXIT_MSG(psa_import_key_wrap(&attributes, psa_import_command, sizeof(psa_import_command), &key_id) == PSA_SUCCESS,
			"Error in importing the client key");
	}
	else {
		ASSERT_OR_EXIT_MSG(psa_status == PSA_SUCCESS,
			"Error in importing the client key");
	}

	ASSERT_OR_EXIT_MSG(mbedtls_pk_setup_opaque(&pkey, key_id) == 0,
		"Error in PK set opaque function to assign the client key to the PK context");
#else
	ASSERT_OR_EXIT_MSG(mbedtls_pk_parse_key(&pkey, client_key, sizeof(client_key), NULL, 0) == 0,
		"Error in injecting client key in PK context");
#endif

	ASSERT_OR_EXIT_MSG(mbedtls_ssl_conf_own_cert(&conf, &client_cert_x509, &pkey) == 0,
		"Error in inserting client certificate in PK context");

	ASSERT_OR_EXIT_MSG(mbedtls_ssl_setup(&ssl, &conf) == 0,
		"Error in setting SSL context");

	ASSERT_OR_EXIT_MSG(mbedtls_ssl_set_hostname(&ssl, hostname) == 0,
		"Error in setting SSL hostname");

    mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    mbedtls_ssl_conf_curves(&conf, supported_curves);

    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            if (ret == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED) {
				EXIT_STATUS_MSG(IOT_AGENT_FAILURE, "mbedtls_ssl_handshake failed with 0x%08x, verify results: 0x%08lx",
                    ret,
                    mbedtls_ssl_get_verify_result(&ssl));
            }

            if (ret == MBEDTLS_ERR_SSL_BAD_INPUT_DATA) {
				EXIT_STATUS_MSG(IOT_AGENT_FAILURE, "MBEDTLS_ERR_SSL_BAD_INPUT_DATA: %d", ret);
            }
        }
    }

exit:
#ifdef MBEDTLS_USE_PSA_CRYPTO
	psa_destroy_key(key_id);
#endif
	do {
		ret = mbedtls_ssl_close_notify(&ssl);
	} while (ret == MBEDTLS_ERR_SSL_WANT_WRITE);

    return (ret);
}

int main()
{
	iot_agent_status_t agent_status = IOT_AGENT_FAILURE;
	agent_status = mbedtls_client_connect();
	AGENT_SUCCESS_OR_EXIT_MSG("Error in agent connection");

    printf("  Press Enter to exit this program.\n");
    fflush(stdout);
    getchar();

exit:
    return (0);
}
