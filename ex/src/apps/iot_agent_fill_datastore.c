/* Copyright 2020, 2021 NXP
*
* SPDX-License-Identifier: Apache-2.0
*/
#include <stdio.h>
#include <stdint.h>

#ifdef _WIN32
#include <direct.h>
#include <dirent_win32.h>
#include <unistd.h>
#else
#include <dirent.h>
#endif

#include <nxp_iot_agent.h>
#include <nxp_iot_agent_session.h>
#include <nxp_iot_agent_macros.h>
#include <nxp_iot_agent_utils.h>
#include <nxp_iot_agent_datastore_fs.h>
#include <nxp_iot_agent_keystore_sss_se05x.h>
#include <nxp_iot_agent_keystore_psa.h>

#if SSS_HAVE_HOSTCRYPTO_OPENSSL
#include <openssl/pem.h>
#elif SSS_HAVE_HOSTCRYPTO_MBEDTLS
#include <mbedtls/x509_crt.h>
#endif

#if NXP_IOT_AGENT_HAVE_SSS
static ex_sss_boot_ctx_t gex_sss_boot_ctx;
#endif


const char * gszEdgeLock2GoDatastoreFilename = "edgelock2go_datastore.bin";


static void print_usage()
{
	printf("Fill a datastore_fs with one service descriptor assembled from commandline parameters:\n");
	printf("usage: \n");
#if IOT_AGENT_HAVE_SSS
	printf("       nxp_iot_agent_fill_datastore [HOST] [PORT] [CA_FILE] [FILE KEYSTORE_ID] [SSS_CONNECTSTRING]\n");
#else
	printf("       nxp_iot_agent_fill_datastore [HOST] [PORT] [CA_FILE] [FILE KEYSTORE_ID]\n");
#endif
	printf("       To omitt an option and fall back to the default, use '-'.\n");
	printf("\n");
	printf("    HOST: The hostname to use for the connection.\n");
	printf("        If omitted, \"%s\" is used.\n", EDGELOCK2GO_HOSTNAME);
	printf("    PORT: The port to use for the connection.\n");
	printf("        If omitted, %d  is used.\n", EDGELOCK2GO_PORT);
	printf("    CA_FILE: Filename of a pem file containing all trusted root CA root_certificates.\n");
	printf("        If omitted, hardcoded sandbox root_certificates are used.\n");
	printf("    CLIENT_CERT_FILE: Filename of a pem file containing the client certificate.\n");
	printf("        If omitted, it is assumed that the certificate is stored in the keystore with \n");
	printf("        the ID given below and the datastore entry is created with a reference to an \n");
    printf("        object for a client certificate.\n");
	printf("\n");
	printf("    FILE: The basename of the datastore file.\n");
	printf("        If omitted, \"%s\" is used.\n", gszEdgeLock2GoDatastoreFilename);
	printf("    KEYSTORE_ID: The keystore id as it is registered in the agent.\n");
	printf("        If omitted, 0x%08xx is used.\n", EDGELOCK2GO_KEYSTORE_ID);
	printf("\n");
#if IOT_AGENT_HAVE_SSS
	printf("    SSS_CONNECTSTRING: The string to connect to the SSS keystore (JRCP_HOSTNAME, JRCP_PORT \n");
	printf("        or VCOM number). The tool will try to find the objectid for key and\n");
	printf("        client certificate on the SSS keystore (ECC preferred, else RSA).\n");
	printf("        For JRCP use ip:port (127.0.0.1:8050), for VCOM usa a virtual com port\n");
	printf("        number (\"COM3\" or \"\\\\.\\COM18\")\n");
	printf("        If omitted, the hardcoded defaults of the selected SM_COMM are used.\n");
	printf("\n");
#define EXPECTED_ARGC (8U)
#else
#define EXPECTED_ARGC (7U)
#endif
}

iot_agent_status_t iot_agent_read_certificates(const char* filename, pb_bytes_array_t** certificates)
{
	iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
#if SSS_HAVE_HOSTCRYPTO_OPENSSL
	FILE* fp = NULL;
	long sz = 0;
	uint8_t* buffer = NULL;

	BIO* bio_in = NULL;
	X509* cert = NULL;

	fp = fopen(filename, "r");
	ASSERT_OR_EXIT_STATUS_MSG(fp != NULL, IOT_AGENT_ERROR_FILE_SYSTEM, "Unable to open file [%s]", filename);
	fseek(fp, 0L, SEEK_END);
	sz = ftell(fp);
	fclose(fp);

	*certificates = malloc(sizeof((*certificates)->size) + (size_t)sz);
	ASSERT_OR_EXIT((*certificates) != NULL);
	(*certificates)->size = 0U;

	bio_in = BIO_new_file(filename, "r");
	ASSERT_OR_EXIT_STATUS_MSG(bio_in != NULL, IOT_AGENT_ERROR_FILE_SYSTEM, "Unable to open file [%s]", filename);

	while (!BIO_eof(bio_in)) {
		cert = PEM_read_bio_X509(bio_in, NULL, NULL, NULL);
		int written = i2d_X509(cert, &buffer);
		ASSERT_OR_EXIT(written >= 0);

		memcpy((*certificates)->bytes + (*certificates)->size, buffer, (size_t)written);
		(*certificates)->size += (size_t)written;

		free(buffer);
		buffer = NULL;

		X509_free(cert);
		cert = NULL;
	}

exit:
	free(buffer);
	X509_free(cert);
	BIO_free(bio_in);
	if (agent_status != IOT_AGENT_SUCCESS) {
		free(*certificates);
		*certificates = NULL;
	}
	return agent_status;

#elif SSS_HAVE_HOSTCRYPTO_MBEDTLS
	mbedtls_x509_crt cert = { 0 };
	int ret = 0;
	size_t size = 0U;
	mbedtls_x509_crt* ci = NULL;
	uint8_t* pos = NULL;

	mbedtls_x509_crt_init(&cert);
	ret = mbedtls_x509_crt_parse_file(&cert, filename);
	ASSERT_OR_EXIT_MSG(ret == 0, "Unable to parse certificates in file [%s]", filename);

	ci = &cert;
	while (ci != NULL) {
		size += ci->raw.len;
		ci = ci->next;
	}

	*certificates = malloc(sizeof((* certificates)->size) + size);
	ASSERT_OR_EXIT(*certificates != NULL);
	(*certificates)->size = size;

	ci = &cert;
	pos = (*certificates)->bytes;
	while (ci != NULL) {
		memcpy(pos, ci->raw.p, ci->raw.len);
		pos += ci->raw.len;
		ci = ci->next;
	}

exit:
	mbedtls_x509_crt_free(&cert);
	if (agent_status != IOT_AGENT_SUCCESS) {
		free(*certificates);
		*certificates = NULL;
	}
	return agent_status;
#endif
}

int main(int argc, const char *argv[])
{
	iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;

	iot_agent_datastore_t datastore = { 0 };
	iot_agent_keystore_t keystore = { 0 };

	const char* hostname = EDGELOCK2GO_HOSTNAME;
	uint32_t port = EDGELOCK2GO_PORT;
	const char* ca_file = NULL;
	const char* client_cert_file = NULL;
	const char* datastore_file = gszEdgeLock2GoDatastoreFilename;
	uint32_t keystore_id = EDGELOCK2GO_KEYSTORE_ID;

	pb_bytes_array_t* root_certificates = NULL;
	const pb_bytes_array_t* root_certificates_ref = iot_agent_trusted_root_ca_certificates;

	pb_bytes_array_t* client_certificate = NULL;



	if (argc != EXPECTED_ARGC || (argc > 1 && strstr(argv[1], "help") != NULL))
	{
		print_usage();
		return -1;
	}

	if (strcmp("-", argv[1]) != 0) {
		hostname = argv[1];
	}

	if (strcmp("-", argv[2]) != 0) {
		port = (uint32_t)strtoul(argv[2], NULL, 0);
	}

	if (strcmp("-", argv[3]) != 0) {
		ca_file = argv[3];
	}

	if (strcmp("-", argv[4]) != 0) {
		client_cert_file = argv[4];
	}

	if (strcmp("-", argv[5]) != 0) {
		datastore_file = argv[5];
	}

	if (strcmp("-", argv[6]) != 0) {
		keystore_id = (uint32_t)strtoul(argv[6], NULL, 0);
	}

#if NXP_IOT_AGENT_HAVE_SSS
	if (strcmp("-", argv[7]) != 0) {
		agent_status = iot_agent_session_init(argc, argv, &gex_sss_boot_ctx);
		AGENT_SUCCESS_OR_EXIT();
	}
	else {
		agent_status = iot_agent_session_init(0, NULL, &gex_sss_boot_ctx);
		AGENT_SUCCESS_OR_EXIT();
}
#endif

	printf("hostname:         %s\n", hostname);
	printf("port:             %d\n", port);
	printf("root_cert_file:   %s\n", ca_file);
	printf("client_cert_file: %s\n", client_cert_file);
	printf("\n");
	printf("output_file:      %s\n", datastore_file);
	printf("keystore_id:      0x%08x (%d)\n", keystore_id, keystore_id);

	agent_status = iot_agent_datastore_fs_init(&datastore, 0U, datastore_file, &iot_agent_service_is_configuration_data_valid);
	AGENT_SUCCESS_OR_EXIT();

#if SSS_HAVE_MBEDTLS_ALT_SSS
	agent_status = iot_agent_keystore_sss_se05x_init(&keystore, keystore_id, &gex_sss_boot_ctx, true);
	AGENT_SUCCESS_OR_EXIT();
#elif SSS_HAVE_MBEDTLS_ALT_PSA
	agent_status = iot_agent_keystore_psa_init(&keystore, keystore_id);
	AGENT_SUCCESS_OR_EXIT();
#endif

	if (ca_file != NULL) {
		agent_status = iot_agent_read_certificates(ca_file, &root_certificates);
		AGENT_SUCCESS_OR_EXIT();
	}
	if (client_cert_file != NULL) {
		agent_status = iot_agent_read_certificates(client_cert_file, &client_certificate);
		AGENT_SUCCESS_OR_EXIT();
	}

	agent_status = iot_agent_utils_write_edgelock2go_datastore(&keystore, &datastore, hostname, port, 
		root_certificates_ref, client_certificate);
	AGENT_SUCCESS_OR_EXIT();

exit:
    iot_agent_datastore_free(&datastore);
    iot_agent_keystore_free(&keystore);
    free(root_certificates);

	return agent_status;
}
