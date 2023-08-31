/*
 * Copyright 2021-2022 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <psa/crypto.h>
#include "psa_init_utils.h"
#include "nxp_iot_agent_macros.h"
#include "nxp_iot_agent_log.h"
#include "nxp_iot_agent_status.h"
#include <string.h>

#define TOTAL_BUF_SIZE (8000)


void print_usage()
{
	printf("Execute Key Import on a S50\n");
	printf("  Usage:\n");
	printf("nxp_iot_agent_psa_init_keystore [key-file]\n");
	printf("\n");
	printf(
		"The perso file contains KEYID, KEYTYPE, Permitted Algorithm, Key Usage and key value, one entry per line in the "
		"following format:\n");
	printf("keydata keyId ECPRIVATE/ECPUBLIC/AEC PERMITTED ALG. KEY USAGE KEY \n");
	printf("All lines not following this format are ignored.\n");
}


int main(int argc, char *argv[])
{
	iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
	psa_status_t psa_status = psa_crypto_init();
	ASSERT_OR_EXIT_MSG(psa_status == PSA_SUCCESS, "Error in psa initialization");

	if (argc != 2) {
		print_usage();
		goto exit;
	}

	FILE *fp = fopen(argv[1], "r");
	if (fp == NULL) {
		IOT_AGENT_ERROR("error opening file %s\n", argv[1]);
		//print_usage();
		goto exit;
	}

	char buf[TOTAL_BUF_SIZE] = { 0 };

	while (fgets(buf, sizeof(buf), fp) != NULL) {
		size_t len = strlen(buf) - 1;

		if (buf[len] == '\r' || buf[len] == '\n') {
			buf[len] = '\0'; // eat the newline fgets() stores
		}

		agent_status = psa_init_utils_import_cmd(buf);
		AGENT_SUCCESS_OR_EXIT_MSG("Error in the import command\n");
	}

	fclose(fp);

	printf("  Press Enter to exit this program.\n");
	fflush(stdout);
	getchar();

exit:
	return (0);
}