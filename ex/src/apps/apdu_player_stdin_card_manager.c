/*
 * Copyright 2020-2021,2024 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

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

#if SSS_HAVE_APPLET_SE05X_IOT
#include <fsl_sss_se05x_apis.h>
#endif

#if defined(__linux__) && defined(T1oI2C)
#if SSS_HAVE_APPLET_SE05X_IOT
#include "ex_sss_main_inc_linux.h"
#endif
#endif

#include "ex_sss_ports.h"
#include <ex_sss_boot.h>
#include "sm_apdu.h"

#include "nxLog_App.h"
#include "PlugAndTrust_Pkg_Ver.h"

#include <global_platf.h>
#include <fsl_sss_se05x_scp03.h>


#define MAX_TX_RX_BUFFER 1024

#define AUTH_KEY_SIZE 16
#define SCP03_MAX_AUTH_KEY_SIZE 52

#define EX_SSS_AUTH_SE05X_KEY_ENC { 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, }
#define EX_SSS_AUTH_SE05X_KEY_MAC EX_SSS_AUTH_SE05X_KEY_ENC
#define EX_SSS_AUTH_SE05X_KEY_DEK EX_SSS_AUTH_SE05X_KEY_ENC

#define COMMAND_PREFIX "/send "
#define RESPONSE_PREFIX "response: "

static ex_sss_boot_ctx_t gex_sss_gen_cert = { 0 };
static uint8_t KEY_ENC[] = EX_SSS_AUTH_SE05X_KEY_ENC;
static uint8_t KEY_MAC[] = EX_SSS_AUTH_SE05X_KEY_MAC;
static uint8_t KEY_DEK[] = EX_SSS_AUTH_SE05X_KEY_DEK;


static void print_binary_as_hexstring(const uint8_t* rx, const size_t rlen) {
		for (size_t i = 0U; i < rlen; i++) {
			printf("%02x", rx[i]);
		}
		printf("\n");
}

static void print_usage()
{
	printf("Communicate to the card manager of an SE on APDU level.\n");
	printf("  Usage:\n");
	printf("apdu_player_stdin_card_manager <connectionString> <options>\n");
	printf("\n");
	printf(
        "Upon startup this application selects the card manager and authenticates. \n"
        "For authentication card manager keys are hardcoded into the application, \n"
		"no secure messaging (neither encryption nor MACs in either direction) are used. \n"
        "After authentication it provides a channel to communicate to the card \n"
        "manager using APDUs. \n"
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
		"To reduce noise, it is an option to recompile with Log=Silent. \n"
		"\n"
		"\n"
        "The keys used for authentication at the card manager are: \n");
    printf(" ENC: ");
    print_binary_as_hexstring(KEY_ENC, sizeof(KEY_ENC));
    printf(" MAC: ");
    print_binary_as_hexstring(KEY_MAC, sizeof(KEY_MAC));
	printf(" DEK: ");
	print_binary_as_hexstring(KEY_DEK, sizeof(KEY_DEK));
}


static sss_status_t ex_sss_boot_se05x_open(ex_sss_boot_ctx_t *pCtx, const char *portName, SE_AuthType_t auth_type)
{
	sss_status_t status = kStatus_SSS_Fail;
	SE_Connect_Ctx_t *pConnectCtx = NULL;
	sss_session_t *pPfSession = NULL;
	sss_connection_type_t connection_type = auth_type == kSE05x_AuthType_None
		? kSSS_ConnectionType_Plain
		: kSSS_ConnectionType_Encrypted;

	pPfSession = &pCtx->session;
	pConnectCtx = &pCtx->se05x_open_ctx;

#if defined(SMCOM_JRCP_V1)
	if (ex_sss_boot_isSocketPortName(portName)) {
		pConnectCtx->connType = kType_SE_Conn_Type_JRCP_V1;
		pConnectCtx->portName = portName;
	}
#endif

#if defined(SMCOM_JRCP_V2)
	if (ex_sss_boot_isSocketPortName(portName)) {
		pConnectCtx->connType = kType_SE_Conn_Type_JRCP_V2;
		pConnectCtx->portName = portName;
	}
#endif

#if defined(RJCT_VCOM)
	if (ex_sss_boot_isSerialPortName(portName)) {
		pConnectCtx->connType = kType_SE_Conn_Type_VCOM;
		pConnectCtx->portName = portName;
	}
#endif

#if defined(SCI2C)
#error "Not a valid  combination"
#endif

#if defined(T1oI2C)
	pConnectCtx->connType = kType_SE_Conn_Type_T1oI2C;
	pConnectCtx->portName = portName;
#endif

#if defined(SMCOM_PCSC)
	pConnectCtx->connType = kType_SE_Conn_Type_PCSC;
	pConnectCtx->portName = portName;
#endif

#if defined(SMCOM_PN7150)
	pConnectCtx->connType = kType_SE_Conn_Type_NFC;
	pConnectCtx->portName = NULL;
#endif

#if defined(SMCOM_RC663_VCOM)
	if (portName == NULL) {
		static const char *sszCOMPort = EX_SSS_BOOT_SSS_COMPORT_DEFAULT;
		portName = sszCOMPort;
	}
	pConnectCtx->connType = kType_SE_Conn_Type_NFC;
	pConnectCtx->portName = portName;
#endif

#if SSS_HAVE_HOSTCRYPTO_ANY
	status = ex_sss_se05x_prepare_host(
		&pCtx->host_session, &pCtx->host_ks, pConnectCtx, &pCtx->ex_se05x_auth, auth_type);

	if (kStatus_SSS_Success != status) {
		LOG_E("ex_sss_se05x_prepare_host failed");
		goto cleanup;
	}
#endif // SSS_HAVE_HOSTCRYPTO_ANY

	if (auth_type == kSSS_AuthType_SCP03 || auth_type == kSSS_AuthType_None) {
		status = sss_session_open(pPfSession, kType_SSS_SE_SE05x, 0, connection_type, pConnectCtx);
		if (kStatus_SSS_Success != status) {
			LOG_E("sss_session_open failed");
			goto cleanup;
		}
	}

cleanup:
	return status;
}


static sss_status_t Alloc_Scp03key_toSE05xAuthctx(sss_object_t *keyObject, sss_key_store_t *pKs, uint32_t keyId)
{
	sss_status_t status = kStatus_SSS_Fail;
	status = sss_host_key_object_init(keyObject, pKs);
	if (status != kStatus_SSS_Success) {
		return status;
	}

	status = sss_host_key_object_allocate_handle(keyObject,
		keyId,
		kSSS_KeyPart_Default,
		kSSS_CipherType_AES,
		SCP03_MAX_AUTH_KEY_SIZE,
		kKeyObject_Mode_Transient);
	return status;
}


static sss_status_t ex_sss_se05x_init_scp_keys(
	NXSCP03_AuthCtx_t *pAuthCtx, ex_SE05x_authCtx_t *pEx_auth, sss_key_store_t *pKs)
{
	sss_status_t status = kStatus_SSS_Fail;

	pAuthCtx->pStatic_ctx = &pEx_auth->scp03.ex_static;
	pAuthCtx->pDyn_ctx = &pEx_auth->scp03.ex_dyn;
	NXSCP03_StaticCtx_t *pStatic_ctx = pAuthCtx->pStatic_ctx;
	NXSCP03_DynCtx_t *pDyn_ctx = pAuthCtx->pDyn_ctx;


	/* Init Allocate ENC Static Key */
	status = Alloc_Scp03key_toSE05xAuthctx(&pStatic_ctx->Enc, pKs, MAKE_TEST_ID(__LINE__));
	if (status != kStatus_SSS_Success) {
		return status;
	}
	/* Set ENC Static Key */
	status = sss_host_key_store_set_key(pKs, &pStatic_ctx->Enc, KEY_ENC, sizeof(KEY_ENC), sizeof(KEY_ENC) * 8, NULL, 0);
	if (status != kStatus_SSS_Success) {
		return status;
	}

	/* Init Allocate MAC Static Key */
	status = Alloc_Scp03key_toSE05xAuthctx(&pStatic_ctx->Mac, pKs, MAKE_TEST_ID(__LINE__));
	if (status != kStatus_SSS_Success) {
		return status;
	}
	/* Set MAC Static Key */
	status = sss_host_key_store_set_key(pKs, &pStatic_ctx->Mac, KEY_MAC, sizeof(KEY_MAC), sizeof(KEY_MAC) * 8, NULL, 0);
	if (status != kStatus_SSS_Success) {
		return status;
	}

	/* Init Allocate DEK Static Key */
	status = Alloc_Scp03key_toSE05xAuthctx(&pStatic_ctx->Dek, pKs, MAKE_TEST_ID(__LINE__));
	if (status != kStatus_SSS_Success) {
		return status;
	}
	/* Set DEK Static Key */
	status = sss_host_key_store_set_key(pKs, &pStatic_ctx->Dek, KEY_DEK, sizeof(KEY_DEK), sizeof(KEY_DEK) * 8, NULL, 0);
	if (status != kStatus_SSS_Success) {
		return status;
	}

	/* Init Allocate ENC Session Key */
	status = Alloc_Scp03key_toSE05xAuthctx(&pDyn_ctx->Enc, pKs, MAKE_TEST_ID(__LINE__));
	if (status != kStatus_SSS_Success) {
		return status;
	}
	/* Init Allocate MAC Session Key */
	status = Alloc_Scp03key_toSE05xAuthctx(&pDyn_ctx->Mac, pKs, MAKE_TEST_ID(__LINE__));
	if (status != kStatus_SSS_Success) {
		return status;
	}
	/* Init Allocate DEK Session Key */
	status = Alloc_Scp03key_toSE05xAuthctx(&pDyn_ctx->Rmac, pKs, MAKE_TEST_ID(__LINE__));
	return status;
}


static sss_status_t ex_sss_se05x_prepare_host_platformscp(sss_session_t *host_session,
	sss_key_store_t *host_ks,
	SE_Connect_Ctx_t *se05x_open_ctx,
	ex_SE05x_authCtx_t *se05x_auth_ctx)
{
	sss_status_t status = kStatus_SSS_Fail;

	if (host_session->subsystem == kType_SSS_SubSystem_NONE) {
		sss_type_t hostsubsystem = kType_SSS_SubSystem_NONE;

#if SSS_HAVE_HOSTCRYPTO_MBEDTLS
		hostsubsystem = kType_SSS_mbedTLS;
#elif SSS_HAVE_HOSTCRYPTO_OPENSSL
		hostsubsystem = kType_SSS_OpenSSL;
#elif SSS_HAVE_HOSTCRYPTO_USER
		hostsubsystem = kType_SSS_Software;
#endif

		status = sss_host_session_open(host_session, hostsubsystem, 0, kSSS_ConnectionType_Plain, NULL);

		if (kStatus_SSS_Success != status) {
			LOG_E("Failed to open Host Session");
			goto cleanup;
		}

		status = sss_host_key_store_context_init(host_ks, host_session);
		if (kStatus_SSS_Success != status) {
			LOG_E("Host: sss_key_store_context_init failed");
			goto cleanup;
		}
		status = sss_host_key_store_allocate(host_ks, __LINE__);
		if (kStatus_SSS_Success != status) {
			LOG_E("Host: sss_key_store_allocate failed");
			goto cleanup;
		}
	}

	status = ex_sss_se05x_init_scp_keys(&se05x_open_ctx->auth.ctx.scp03, se05x_auth_ctx, host_ks);
	if (kStatus_SSS_Success != status) {
		LOG_E("Host: ex_sss_se05x_init_scp_keys failed");
		goto cleanup;
	}
	se05x_open_ctx->auth.authType = kSSS_AuthType_SCP03;

cleanup:
	return status;
}


int main(int argc, const char *argv[])
{
	int ret;
	sss_status_t status = kStatus_SSS_Fail;
	char *portName;

	for (int i = 0; i < argc; i++) {
		if ((strcmp(argv[i], "-h") == 0)
			|| (strcmp(argv[i], "--help") == 0)) {
			print_usage();
			return kStatus_SSS_Fail;
		}
	}

#if defined(__linux__) && defined(T1oI2C) && SSS_HAVE_APPLET_SE05X_IOT
	ex_sss_main_linux_conf();
#endif // defined(__linux__) && defined(T1oI2C) && SSS_HAVE_APPLET_SE05X_IOT

	LOG_I(PLUGANDTRUST_PROD_NAME_VER_FULL);

	status = ex_sss_boot_connectstring(argc, argv, &portName);
	if (kStatus_SSS_Success != status) {
		LOG_E("ex_sss_boot_connectstring Failed");
		goto cleanup;
	}

	gex_sss_gen_cert.se05x_open_ctx.skip_select_applet = 1;
	gex_sss_gen_cert.se05x_open_ctx.auth.authType = kSSS_AuthType_None;

	status = ex_sss_boot_se05x_open(&gex_sss_gen_cert, portName, gex_sss_gen_cert.se05x_open_ctx.auth.authType);
	if (kStatus_SSS_Success != status) {
		LOG_E("ex_sss_session_open Failed");
		goto cleanup;
	}

	if (kType_SSS_SubSystem_NONE == (gex_sss_gen_cert.session.subsystem)) {
		/* Nothing to do. Device is not opened
		* This is needed for the case when we open a generic communication
		* channel, without being specific to SE05X
		*/
	}
	else {
		status = ex_sss_kestore_and_object_init(&gex_sss_gen_cert);
		if (kStatus_SSS_Success != status) {
			LOG_E("ex_sss_kestore_and_object_init Failed");
			goto cleanup;
		}
	}


	// Select card manager
	ex_sss_boot_ctx_t* pCtx = &gex_sss_gen_cert;
	U8 selectResponseData[256] = { 0 };
	U16 selectResponseDataLen = (U16) sizeof(selectResponseData);
	GP_Select(((sss_se05x_session_t *)&pCtx->session)->s_ctx.conn_ctx, NULL, 0, selectResponseData, &selectResponseDataLen);

	// Authenticate using platform scp
	SE05x_Connect_Ctx_t *pAuthCtx = NULL;
	pAuthCtx = (SE05x_Connect_Ctx_t *)&pCtx->se05x_open_ctx;
	pAuthCtx->auth.authType = kSSS_AuthType_SCP03;
	Se05xSession_t* se05xSession = &((sss_se05x_session_t *)&pCtx->session)->s_ctx;

	status = ex_sss_se05x_prepare_host_platformscp(&pCtx->host_session, &pCtx->host_ks, pAuthCtx, &pCtx->ex_se05x_auth);

	se05xSession->fp_Transform = &se05x_Transform;
	se05xSession->fp_DeCrypt = &se05x_DeCrypt;
	status = nxScp03_AuthenticateChannel(se05xSession, &pAuthCtx->auth.ctx.scp03);
	if (status != kStatus_SSS_Success) {
		LOG_E("Could not set SCP03 Secure Channel");
		return kStatus_SSS_Fail;
	}

	// Attention: Normally one would change the function pointers
	// to se05x_Transform_scp and se05x_DeCrypt here and use a high-level DoAPDUTxRx
	// which would take care of the secure channel.
	// However, the hostlib has a hardcoded security level (ENC + MAC on command and
	// response) in the authentication and in those functions, we do need, however to
	// use no secure messaging in order to be able to install the applet and to configure
	// the comm buffer size.
	// That's why we need to
	//   a) patch the hostlib to use hardoced security level NONE instead
	//   b) still use transmit_raw (which essentially is the same as security
	//      level NONE (just bypassing the secure channel)).
	// While this is a bit of an ugly workaround, changing hostlib to a configurable
	// security level is not in scope right now.

	status = ex_sss_entry(&gex_sss_gen_cert);
	LOG_I("ex_sss Finished");
	if (kStatus_SSS_Success != status) {
		LOG_E("ex_sss_entry Failed");
		goto cleanup;
	}

	goto cleanup;
cleanup:
#if defined(_MSC_VER)
    if (portName) {
        char* dummy_portName = NULL;
        size_t dummy_sz = 0;
        _dupenv_s(&dummy_portName, &dummy_sz, EX_SSS_BOOT_SSS_PORT);
        if (NULL != dummy_portName) {
            free(dummy_portName);
            free(portName);
        }
    }
#endif // _MSC_VER

	ex_sss_session_close(&gex_sss_gen_cert);
	if (kStatus_SSS_Success == status) {
		ret = 0;
#if defined(__linux__) && defined(T1oI2C) && SSS_HAVE_APPLET_SE05X_IOT
		ex_sss_main_linux_unconf();
#endif // defined(__linux__) && defined(T1oI2C) && SSS_HAVE_APPLET_SE05X_IOT
	}
	else {
		LOG_E("!ERROR! ret != 0.");
		ret = 1;
	}
	return ret;
}


sss_status_t ex_sss_entry(ex_sss_boot_ctx_t *pCtx)
{
    sss_status_t status = kStatus_SSS_Fail;

    void * conn_ctx = NULL;
	Se05xSession_t* se05x_session = NULL;

#if SSS_HAVE_APPLET_SE05X_IOT
    conn_ctx = ((sss_se05x_session_t *)&pCtx->session)->s_ctx.conn_ctx;
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
		U32 rlen = (U32) sizeof(rx);

		smStatus_t sm_comm_status = smCom_TransceiveRaw(conn_ctx, apdu, (U16)apdu_len, &rx[0], &rlen);

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
