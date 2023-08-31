/*
 * Copyright 2020-2021 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <fsl_sscp_a71ch.h>
#include <fsl_sss_api.h>
#include <smCom.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(SSS_USE_FTR_FILE)
#include "fsl_sss_ftr.h"
#else
#include "fsl_sss_ftr_default.h"
#endif

#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
#include <fsl_sss_mbedtls_apis.h>
#include <mbedtls/version.h>
#endif

#if SSS_HAVE_HOSTCRYPTO_OPENSSL
#include <fsl_sss_openssl_apis.h>
#include <openssl/opensslv.h>
#endif

#if SSS_HAVE_SSCP
#include <fsl_sss_sscp.h>
#include <sm_types.h>
#endif

#if SSS_HAVE_APPLET_SE05X_IOT
#include <fsl_sss_se05x_apis.h>
#endif

#if SSS_HAVE_A71XX
#include <HLSEAPI.h>
#include <fsl_sscp_a71ch.h>
#endif
#if SSS_HAVE_APPLET_A71CL || SSS_HAVE_APPLET_SE05X_L
#include <a71cl_api.h>
#include <fsl_sscp_a71cl.h>
#endif /* SSS_HAVE_APPLET_A71CH / EAR */

#include <ex_sss_boot.h>
#include "sm_apdu.h"

#include "nxLog_App.h"

#define MAX_TX_RX_BUFFER 1024

static ex_sss_boot_ctx_t gex_sss_gen_cert;

#define EX_SSS_BOOT_PCONTEXT (&gex_sss_gen_cert)
#define EX_SSS_BOOT_DO_ERASE 0
#define EX_SSS_BOOT_EXPOSE_ARGC_ARGV 1

#include <ex_sss_main_inc.h>

#define COMMAND_PREFIX "/send "
#define RESPONSE_PREFIX "response: "

static void print_usage()
{
	printf("Execute APDUs on a SE.\n");
	printf("  Usage:\n");
	printf("apdu_player_stdin <connectionString>\n");
	printf("\n");
	printf("Upon startup this application selects the iot applet. \n");
#if SSS_HAVE_SE05X_AUTH_PLATFSCP03
	printf(
		"Also, it will autenticate to the SD of the applet (platform SCP), using \n"
		"full secure messaging. \n");
#endif
	printf("It provides a channel to communicate to the applet manager using APDUs. \n"
        "\n"
        "The following command line arguments are supported: \n"
		"\n");
	printf(
		"connectionString: connectionString is passed on to smCom. It can be \"hostname:port\" for \n"
		"  connecting to simulators when compiled for JRCP_V2 or a COM port when \n"
		"  compiled for VCOM.\n"
		"\n"
		"options: The following options are supported:\n"
		"  -h --help: Dispay usage information. \n"
		"\n"
		"\n"
		"APDUs are read from stdin - one APDU per line, responses are output to stdout.\n"
		"The input APDUs are expected to be hex-strings prefixed with \"" COMMAND_PREFIX "\", \n"
		"without any whitespace or demimiter. \n"
		"Lines that do not follow that convention are ignored. \n"
		"The maximum number of bytes in one APDU is %d.\n\n", SE05X_MAX_BUF_SIZE_CMD);
	printf(
        "Note: As also log messages (e.g. from smCom) are printed to stdout, to be able to \n"
		"distinguish APDU responses (the communication channel) from noise, responses are always \n"
		"prefixed with \"" RESPONSE_PREFIX "\". \n"
		"To reduce noise, it is an option to recompile with Log=Silent. \n");
}


sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status = kStatus_SSS_Fail;
	Se05xSession_t * se05x_session = NULL;

	for (int i = 0; i < gex_sss_argc; i++) {
		if ((strcmp(gex_sss_argv[i], "-h") == 0)
			|| (strcmp(gex_sss_argv[i], "--help") == 0)) {
			print_usage();
			return kStatus_SSS_Fail;
		}
	}


#if SSS_HAVE_APPLET_SE05X_IOT
    se05x_session = &((sss_se05x_session_t *)&pCtx->session)->s_ctx;
#endif

    char buf[MAX_TX_RX_BUFFER * 8] = {0};

    while (fgets(buf, (int)sizeof(buf), stdin) != NULL) {
        size_t len = strlen(buf) - 1;

        if (buf[len] == '\r' || buf[len] == '\n') {
            buf[len] = '\0'; // eat the newline fgets() stores
        }

		int found = strncmp(buf, COMMAND_PREFIX, strlen(COMMAND_PREFIX));
		if (found != 0) {
			LOG_I("discarding [%s]", buf);
			continue;
		}

		uint8_t apdu[SE05X_MAX_BUF_SIZE_CMD] = { 0 };
		size_t apdu_len = 0U;

		if (!smApduGetArrayBytes(buf + strlen(COMMAND_PREFIX), &apdu_len, apdu, SE05X_MAX_BUF_SIZE_CMD)) {
			LOG_E("invalid hexstr in [%s]\n", buf);
			return kStatus_SSS_Fail;
		}


        uint8_t rx[MAX_TX_RX_BUFFER] = {0};
		size_t rlen = sizeof(rx);

		smStatus_t sm_comm_status = DoAPDUTxRx(se05x_session, apdu, apdu_len, &rx[0], &rlen);
		if (sm_comm_status != SM_OK)
		{
			// If the APDU exchange was not successful, one of the reasons is that the SW is not 9000. We do, however,
			// want to have the SW on the caller side. The SW is returned by the APDU exchange function (it can also
			// be SM_NOT_OK, but thats also valuable information), so in this case we put the return value into
			// the rx buffer.
			rx[0] = (uint8_t)(sm_comm_status >> 8) & 0xFFU;
			rx[1] = (uint8_t)sm_comm_status & 0xFFU;
			rlen = 2;
		}

		printf(RESPONSE_PREFIX);
		for (size_t i = 0U; i < rlen; i++) {
			printf("%02x", rx[i]);
		}
		printf("\n");
		fflush(stdout);
    }

    status = kStatus_SSS_Success;
    LOG_I("Example finished successfully");
    return status;
}
