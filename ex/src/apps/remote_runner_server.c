/*
 * Copyright 2018-2024 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */
// Includes for all the builds
#include <stdarg.h>
#include <string.h>
#include <inttypes.h>
#include <nxp_iot_agent.h>
#include <nxp_iot_agent_utils.h>
#include <nxp_iot_agent_keystore.h>
#include <nxp_iot_agent_datastore.h>
#include <nxp_iot_agent_macros.h>
#include <iot_agent_demo_config.h>
#include <iot_agent_rtp_client.h>
#include <nxp_iot_agent_utils.h>
#include <iot_agent_claimcode_encrypt.h>

#include "Dispatcher.pb.h"
#include "Apdu.pb.h"
#include "pb.h"
#include "pb_encode.h"
#include "pb_decode.h"

#if NXP_IOT_AGENT_HAVE_SSS
#include <nxp_iot_agent_keystore_sss_se05x.h>
#include "nxp_iot_agent_macros_sss.h"
#include <nxp_iot_agent_session.h>
#include <fsl_sss_se05x_apis.h>
#include <se05x_APDU_apis.h>
#include <se05x_ecc_curves.h>
#include <smCom.h>
#include "sm_apdu.h"
#include <ex_sss_boot.h>
#endif
#if NXP_IOT_AGENT_HAVE_PSA
#include <nxp_iot_agent_keystore_psa.h>
#include "nxp_iot_agent_macros_psa.h"
#include "psa_init_utils.h"
#include <psa/crypto.h>
#endif

#if defined(_WIN32)
// Includes in case of Windows build
#include <WinSock2.h>
#include <ws2tcpip.h>
#include <dirent_win32.h>

#elif !(defined(AX_EMBEDDED) && defined(USE_RTOS) && USE_RTOS == 1)
// Includes in case of Linux build
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <pthread.h>
#include <dirent.h>

#else
#if defined(LPC_ENET)
// Includes in case of K64F build
#ifndef INC_FREERTOS_H /* Header guard of FreeRTOS */
#include "FreeRTOS.h"
#include "FreeRTOSConfig.h"
#endif /* INC_FREERTOS_H */
#include "task.h"
#include "lwip/opt.h"
#include "lwip/tcpip.h"
#include "lwip/inet.h"
#include "lwip/sockets.h"
#elif defined(LPC_WIFI)
#include "iot_wifi.h"
#include "wifi_config.h"
#include "serial_mwm.h"
#include "serial_mwm_server.h"
#endif
#include <iot_agent_network.h>
#include <iot_agent_osal_freertos.h>
#endif

#if NXP_IOT_AGENT_HAVE_HOSTCRYPTO_MBEDTLS
// Includes in case of MBED TLS
#include <mbedtls/version.h>
#include <iot_agent_mqtt_freertos.h>
#endif

#if NXP_IOT_AGENT_HAVE_SSS
#include <fsl_sss_mbedtls_apis.h>
#endif

#if NXP_IOT_AGENT_HAVE_HOSTCRYPTO_OPENSSL
#include <unistd.h>
#include <iot_agent_mqtt_paho.h>
#ifdef _MSC_VER
#define ACCESS _access
#else
#define ACCESS access
#endif
#endif
#if ((NXP_IOT_AGENT_HAVE_HOSTCRYPTO_OPENSSL) || (AX_EMBEDDED && defined(USE_RTOS) && USE_RTOS == 1))
#define OBJECT_ID_SIZE 10U
#define COMMON_NAME_MAX_SIZE 256
#define COS_OVER_RTP_CERT_SIZE 2048
#endif
#include <nxp_iot_agent_time.h>

#ifdef FLOW_VERBOSE
#define FPRINTF(s_, ...) printf((s_), ##__VA_ARGS__);
#else
#define FPRINTF(...);
#endif

// RPC communication defines
#define RPC_ID	5

#define RPC_ARGUMENT_POS_CMD		0
#define RPC_ARGUMENT_POS_OFFSET		1
#define RPC_ARGUMENT_POS_SIZE		2
#define RPC_ARGUMENT_POS_DATA		3

#define RPC_REQUEST_CMD_START						0U
#define RPC_REQUEST_CMD_STOP						1U
#define RPC_REQUEST_CMD_WAIT						2U
#define RPC_REQUEST_CMD_GET_LOG_LENGTH				3U
#define RPC_REQUEST_CMD_GET_LOG						4U
#define RPC_REQUEST_CMD_SEND_CMD_LENGTH				5U
#define RPC_REQUEST_CMD_SEND_CMD					6U
#define RPC_REQUEST_CMD_STOP_AND_CLOSE				7U
#define RPC_REQUEST_CMD_IS_RUNNING					8U
#define RPC_REQUEST_CMD_WRITE_PEM					9U
#define RPC_REQUEST_CMD_FACTORY_RESET				10U
#define RPC_REQUEST_CMD_GET_RESP_LENGTH				11U
#define RPC_REQUEST_CMD_GET_RESP					12U
#define RPC_REQUEST_CMD_SET_ECC_CURVE				13U
#define RPC_REQUEST_CMD_CONNECT_SERVICES			14U
#define RPC_REQUEST_CMD_INTIALIZE_AGENT				15U
#define RPC_REQUEST_CMD_START_PROVISIONING_CLIENT	16U
#define RPC_REQUEST_CMD_ENDPOINT_REQUEST			17U
#define RPC_REQUEST_CMD_COS_OVER_RTP				18U
#define RPC_REQUEST_CMD_EXECUTE_PSA_API				19U
#define RPC_REQUEST_CMD_PSA_INJECT_CLAIM_CODE		20U

#define RPC_RESPONSE_STATE_SUCCESS	0U
#define RPC_RESPONSE_STATE_ERROR	1U


#if NXP_IOT_AGENT_HAVE_PSA
#define RPC_ARGUMENT_POS_PSA_OPERATION	1
#define RPC_ARGUMENT_POS_PSA_OBJECT_ID	2
#define RPC_ARGUMENT_POS_PSA_ALGORITHM	3
#define RPC_ARGUMENT_POS_PSA_INPUT		4
#define RPC_ARGUMENT_POS_PSA_ADDITIONAL	5
#endif

#define TEST_LOG_ID_REGISTER_ENDPOINT   "register_endpoint"
#define TEST_LOG_ID_EDGELOCK2GO_CONNECT "edgelock2go_connect"
#define TEST_LOG_ID_TCP_CONNECT			"tcp_connect"
#define TEST_LOG_ID_STATUS_REPORT       "status_report"
#define TEST_LOG_ID_PROVISIONED_SERVICE "provisioned_service"
#define TEST_LOG_ID_CONNECTED_SERVICE   "connected_service"
#define TEST_LOG_ID_TERMINATED          "terminated"
#define TEST_LOG_ID_PERFORMANCE         "performance_timing"

#define IOT_AGENT_TEST_ENDPOINT_SE05X     "SE05X"

#define LOG_SIZE 8096U

#define MAX_TX_RX_BUFFER 1024U

#define MAX_PSA_KEY_SIZE 4096

#if defined(LPC_ENET)
#define EX_SSS_BOOT_RTOS_STACK_SIZE (1024*16)
#elif defined(LPC_WIFI)
#define EX_SSS_BOOT_RTOS_STACK_SIZE (1024*20)

#define closesocket(a) mwm_close(a)
#endif

#if ! defined(_WIN32)
#    if ! defined closesocket
#        define closesocket(a) close(a)
#    endif
#endif

#if NXP_IOT_AGENT_HAVE_SSS
// global variables declaration
static ex_sss_boot_ctx_t gex_sss_boot_ctx;
#endif

iot_agent_status_t remote_runner_start(int argc, const char *argv[]);

const char * gszEdgeLock2GoDatastoreFilename = "edgelock2go_datastore.bin";
const char * gszDatastoreFilename = "datastore.bin";
const char * gszKeystoreFilename = "keystore.bin";
const uint32_t gKeystoreId = 0x0000BEEFU;
const char* output_directory = "output";

// the defualt port
const char* gserver_port = "25000";
char local_buffer[LOG_SIZE];
char* log_ptr = NULL;
char* start_log_ptr = NULL;
char* start_cmd_ptr = NULL;
char* cmd_ptr = NULL;
size_t cmd_length = 0;

char* resp_apdu_ptr = NULL;
size_t resp_apdu_length;

bool getRespString(char *str, uint8_t *buffer, size_t buffer_len);

#if NXP_IOT_AGENT_HAVE_HOSTCRYPTO_OPENSSL
static iot_agent_status_t execute_write_pem_test(sss_key_store_t* sss_context, const char* object_id)
{
	iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
	sss_status_t sss_status;
	uint32_t objid = 0U;
	int remove_check = 0;
	iot_agent_keystore_t keystore = { 0 };

#if defined(_WIN32) && (_WIN32 == 1)
	objid = (uint32_t)_strtoi64(object_id, NULL, 0);
#else
	objid = (uint32_t)strtoull(object_id, NULL, 0);
#endif

	char filename[24] = "ObjRef_0x";

	snprintf(filename + 9, sizeof(filename) - 9, "%X", objid);

	strcat(filename, ".pem");
	if (ACCESS(filename, F_OK) == 0)
	{
		remove_check = remove(filename);
		ASSERT_OR_EXIT(remove_check == 0);
	}

	sss_object_t obj;
	sss_status = sss_key_object_init(&obj, sss_context);
	SSS_SUCCESS_OR_EXIT_MSG("sss_key_object_init failed with 0x%04x", sss_status);

	/* Read the key handle using the specific objid*/
	sss_status = sss_key_object_get_handle(&obj, objid);
	SSS_SUCCESS_OR_EXIT_MSG("sss_key_object_get_handle failed with 0x%04x", sss_status);


	switch (obj.cipherType)
	{
	case kSSS_CipherType_RSA:     /* RSA RAW format      */
	case kSSS_CipherType_RSA_CRT: /* RSA CRT format      */
	case kSSS_CipherType_EC_NIST_P: /* Keys Part of NIST-P Family */
	case kSSS_CipherType_EC_NIST_K: /* Keys Part of NIST-K Family */
	case kSSS_CipherType_EC_MONTGOMERY: /* Montgomery Key,   */
	case kSSS_CipherType_EC_TWISTED_ED: /* twisted Edwards form elliptic curve public key */
	case kSSS_CipherType_EC_BRAINPOOL: /* Brainpool form elliptic curve public key */
		agent_status = iot_agent_utils_write_key_ref_pem(sss_context, &obj, objid, filename);
		AGENT_SUCCESS_OR_EXIT_MSG("Failed to create keyref file")
			printf("Generated Key reference file for ObjectId 0x%x in %s \n", objid, filename);
		break;
	case kSSS_CipherType_Certificate: /* Certificate */
	case kSSS_CipherType_Binary: /* Binary */
		agent_status = iot_agent_keystore_sss_se05x_init(&keystore, 0, &gex_sss_boot_ctx, true);
		AGENT_SUCCESS_OR_EXIT_MSG("iot_agent_keystore_sss_se05x_init failed: 0x%08x", agent_status);
		agent_status = iot_agent_utils_write_certificate_pem_from_keystore(&keystore, objid, filename);
		AGENT_SUCCESS_OR_EXIT_MSG("Failed to write certificate file")
			printf("Generated Certificate file for ObjectId 0x%x in %s \n", objid, filename);
		break;
	default:
		printf("The object ID is not a valid Key or Certificate\n");
		agent_status = IOT_AGENT_FAILURE;
	}
exit:
	iot_agent_keystore_free(&keystore);
	return agent_status;
}
#endif

static void write_log(const char* ID, const char* format, ...)
{
	va_list args;
	va_list args_copy;

	// In the function there are checks to not overflow the test log; in case more services
	// are provisioned, they are not logged. A test case which is checking the log will fail
	// with saying that the expected number of services is not compliant with the actual one
	// With the actual memory size the get log works well up to 8 services
	printf("TEST_LOG(%s): ", ID);
	if (((size_t)(log_ptr - start_log_ptr)) < LOG_SIZE)
		log_ptr += snprintf(log_ptr, LOG_SIZE - (size_t)(log_ptr - start_log_ptr), "TEST_LOG(%s): ", ID);

	va_start(args, format);
	va_copy(args_copy, args);
	vprintf(format, args);
	if (((size_t)(log_ptr - start_log_ptr)) < LOG_SIZE)
		log_ptr += vsnprintf(log_ptr, LOG_SIZE - (size_t)(log_ptr - start_log_ptr), format, args_copy);
	va_end(args_copy);
	va_end(args);

	printf("\n");
	if (((size_t)(log_ptr - start_log_ptr)) < LOG_SIZE)
		log_ptr += snprintf(log_ptr, LOG_SIZE - (size_t)(log_ptr - start_log_ptr), "\n");
}


// The function search in the RPC request arguments to find where the
// argument with the specific position value is stored
static iot_agent_status_t search_argument_per_position(nxp_iot_RpcRequest* pRpcRequest, int rpc_position, int* pIndex)
{
	iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
	int i;

	*pIndex = 0;

	for (i = 0; i < (int)pRpcRequest->arg_count; i++)
	{
		if (pRpcRequest->arg[i].pos == rpc_position)
		{
			break;
		}
	}

	ASSERT_OR_EXIT_MSG(i != (int)pRpcRequest->arg_count, "Command argument is missing in the packet\n");

	*pIndex = i;
exit:
	return agent_status;
}

// This function builds the response with only one argument set to the status value
static void build_rpc_response_status(nxp_iot_RpcResponse* pRpcResponse, size_t status)
{
	nxp_iot_Argument outArg0 = nxp_iot_Argument_init_default;

	// build the response, the first argument is setting up the state
	pRpcResponse->has_id = true;
	pRpcResponse->id = RPC_ID;
	pRpcResponse->arg_count = 1U;
	outArg0.has_pos = true;
	outArg0.pos = RPC_ARGUMENT_POS_CMD;
	outArg0.has_payload = true;
	outArg0.payload.which_data = nxp_iot_ArgumentPayload_uint32_arg_tag;
	outArg0.payload.data.uint32_arg = (uint32_t)status;
	pRpcResponse->arg[0] = outArg0;

}

static void build_rpc_response_get_string_length(nxp_iot_RpcResponse* pRpcResponse, size_t status, size_t size)
{
	nxp_iot_Argument outArg0 = nxp_iot_Argument_init_default;
	nxp_iot_Argument outArg1 = nxp_iot_Argument_init_default;

	// build the response, the first argument is setting up the state
	pRpcResponse->has_id = true;
	pRpcResponse->id = RPC_ID;
	pRpcResponse->arg_count = 2U;

	outArg0.has_pos = true;
	outArg0.pos = RPC_ARGUMENT_POS_CMD;
	outArg0.has_payload = true;
	outArg0.payload.which_data = nxp_iot_ArgumentPayload_uint32_arg_tag;
	outArg0.payload.data.uint32_arg = (uint32_t)status;
	pRpcResponse->arg[0] = outArg0;

	outArg1.has_pos = true;
	outArg1.pos = RPC_ARGUMENT_POS_SIZE;
	outArg1.has_payload = true;
	outArg1.payload.which_data = nxp_iot_ArgumentPayload_uint32_arg_tag;
	outArg1.payload.data.uint32_arg = (uint32_t)size;
	pRpcResponse->arg[1] = outArg1;

}

static void build_rpc_response_get_string(nxp_iot_RpcResponse* pRpcResponse, size_t status, size_t offset, size_t size, char* data)
{
	nxp_iot_Argument outArg0 = nxp_iot_Argument_init_default;
	nxp_iot_Argument outArg1 = nxp_iot_Argument_init_default;
	nxp_iot_Argument outArg2 = nxp_iot_Argument_init_default;
	nxp_iot_Argument outArg3 = nxp_iot_Argument_init_default;

	// build the response, the first argument is setting up the state
	pRpcResponse->has_id = true;
	pRpcResponse->id = RPC_ID;
	pRpcResponse->arg_count = 4U;

	outArg0.has_pos = true;
	outArg0.pos = RPC_ARGUMENT_POS_CMD;
	outArg0.has_payload = true;
	outArg0.payload.which_data = nxp_iot_ArgumentPayload_uint32_arg_tag;
	outArg0.payload.data.uint32_arg = (uint32_t)status;
	pRpcResponse->arg[0] = outArg0;

	outArg1.has_pos = true;
	outArg1.pos = RPC_ARGUMENT_POS_OFFSET;
	outArg1.has_payload = true;
	outArg1.payload.which_data = nxp_iot_ArgumentPayload_uint32_arg_tag;
	outArg1.payload.data.uint32_arg = (uint32_t)offset;
	pRpcResponse->arg[1] = outArg1;

	outArg2.has_pos = true;
	outArg2.pos = RPC_ARGUMENT_POS_SIZE;
	outArg2.has_payload = true;
	outArg2.payload.which_data = nxp_iot_ArgumentPayload_uint32_arg_tag;
	outArg2.payload.data.uint32_arg = (uint32_t)size;
	pRpcResponse->arg[2] = outArg2;

	outArg3.has_pos = true;
	outArg3.pos = RPC_ARGUMENT_POS_DATA;
	outArg3.has_payload = true;
	outArg3.payload.which_data = nxp_iot_ArgumentPayload_string_arg_tag;

	for (size_t i = 0U; i < size; i++)
	{
		outArg3.payload.data.string_arg[i] = *(data + offset + i);
	}

	pRpcResponse->arg[3] = outArg3;
}

// This function parses the get string command
static iot_agent_status_t parse_get_string_command(nxp_iot_RpcRequest* pRpcRequest, size_t* pOffset, size_t* pSize)
{
	*pOffset = 0U;
	*pSize = 0U;
	iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
	ASSERT_OR_EXIT_MSG(pRpcRequest->arg_count >= 3U, "At least one argument needs to be present in the packet\n");

	// check if the offset field is present and read the value
	int offset_index;
	agent_status = search_argument_per_position(pRpcRequest, RPC_ARGUMENT_POS_OFFSET, &offset_index);
	AGENT_SUCCESS_OR_EXIT_MSG("Offset argument is missing in the packet\n");
	*pOffset = pRpcRequest->arg[offset_index].payload.data.uint32_arg;

	// check if the size field is present and read the value
	int size_index;
	agent_status = search_argument_per_position(pRpcRequest, RPC_ARGUMENT_POS_SIZE, &size_index);
	AGENT_SUCCESS_OR_EXIT_MSG("Size argument is missing in the packet\n");
	*pSize = pRpcRequest->arg[size_index].payload.data.uint32_arg;
exit:
	return agent_status;
}

// This function parses the get string command
static iot_agent_status_t parse_cos_over_rtp_command(nxp_iot_RpcRequest* pRpcRequest, size_t* pServiceDescriptorId)
{
	*pServiceDescriptorId = 0U;
	iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
	ASSERT_OR_EXIT_MSG(pRpcRequest->arg_count >= 2U, "At least one argument needs to be present in the packet\n");

	// check if the offset field is present and read the value
	int offset_index;
	agent_status = search_argument_per_position(pRpcRequest, RPC_ARGUMENT_POS_OFFSET, &offset_index);
	AGENT_SUCCESS_OR_EXIT_MSG("Offset argument is missing in the packet\n");
	*pServiceDescriptorId = pRpcRequest->arg[offset_index].payload.data.uint32_arg;

exit:
	return agent_status;
}

#if (defined(AX_EMBEDDED) && defined(USE_RTOS) && USE_RTOS == 1)
// helper function used just in the freeRTOS to solve issues
// in hex string formatting
static int convertHexByteInStr(char *char_ptr, uint8_t buffer_byte)
{
	uint8_t temp = 0;
	char actual_char = '0';
	for (int i = 0; i < 2; i++)
	{
		temp = (buffer_byte >> (4 * (1 - i)));
		temp &= 0x0F;

		if (temp <= 9)
		{
			actual_char = '0' + temp;
		}
		else if ((temp >= 10) && (temp <= 16))
		{
			actual_char = (temp - 10) + 'A';
		}
		else
		{
			return 0;
		}
		*(char_ptr + i) = actual_char;
	}
	return 1;
}

// helper function used just in the freeRTOS to solve issues
// in hex string formatting
static int convertCharInHexByte(char *char_ptr, uint8_t* buffer_byte)
{
	uint8_t temp;
	char actual_char;
	*buffer_byte = 0;

	for (int i = 0; i < 2; i++)
	{
		*buffer_byte <<= 4;
		*buffer_byte &= 0xF0;
		actual_char = *(char_ptr + i);
		if ((actual_char >= '0') && (actual_char <= '9'))
		{
			temp = actual_char - '0';
		}
		else if ((actual_char >= 'A') && (actual_char <= 'F'))
		{
			temp = (actual_char - 'A') + 10;
		}
		else if ((actual_char >= 'a') && (actual_char <= 'f'))
		{
			temp = (actual_char - 'a') + 10;
		}
		else
		{
			return 0;
		}
		*buffer_byte += temp;
	}
	return 1;
}

// helper function used just in the freeRTOS to solve issues
// in hex string formatting
static bool convertApduStrInHexArray(char *str, size_t *len, uint8_t *buffer, size_t buffer_len)
{
    if ((strlen(str) % 2) != 0) {
        LOG_E("Invalid length");
        return false;
    }

    *len = strlen(str) / 2;
    if (buffer_len < *len)
    {
        LOG_E("Insufficient buffer size\n");
        *len = 0;
        return false;
    }
    char *pos = str;
    for (size_t count = 0U; count < *len; count++) {
        if (convertCharInHexByte(pos, &buffer[count]) < 1) {
            *len = 0;
            return false;
        }
        pos += 2;
    }
    return true;
}
#endif
// this function gets the response string from the received hex buffer
bool getRespString(char *str, uint8_t *buffer, size_t buffer_len)
{
	char* pos = str;
	for (size_t count = 0U; count < buffer_len; count++) {

#if (defined(AX_EMBEDDED) && defined(USE_RTOS) && USE_RTOS == 1)
		if (convertHexByteInStr(pos, buffer[count]) < 1)
#else
		if (sprintf(pos, "%02hhX", buffer[count]) < 1)
#endif
		{
			return false;
		}
		pos += 2;
	}

	return true;
}

#if NXP_IOT_AGENT_HAVE_SSS

// this function sends an APDU to device and checks response
static iot_agent_status_t send_apdu_to_device(void)
{
	iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;

	char buf[MAX_TX_RX_BUFFER * 8] = { 0 };
	char apdu_str[(SE05X_MAX_BUF_SIZE_CMD * 2) + 1] = { 0 };
	char resp_str[(SE05X_MAX_BUF_SIZE_RSP * 2) + 1] = { 0 };
	uint8_t apdu[SE05X_MAX_BUF_SIZE_CMD] = { 0U };
	uint8_t resp[SE05X_MAX_BUF_SIZE_RSP] = { 0U };
	size_t apdu_len = 0U;
	size_t resp_len = 0U;
	char *resp_to_compare_str = NULL;
	uint8_t rx[MAX_TX_RX_BUFFER];
    size_t rlen = sizeof(rx);
	bool compare_response = false;

	memcpy(buf, start_cmd_ptr, cmd_length);
	size_t len = strlen(buf);
	buf[len] = '\0'; // eat the newline fgets() stores

	// This is used for initialization only, hence it is somewhat safe to bypass the keystore
	// here and access the context directly.
    sss_se05x_session_t *pSession = (sss_se05x_session_t *)&gex_sss_boot_ctx.session;

	int found = sscanf(buf, "/send %s %s", apdu_str, resp_str);
	if (found <= 0) {
		IOT_AGENT_DEBUG("discarding [%s]\n", buf);
		goto exit;
	}

#if (defined(AX_EMBEDDED) && defined(USE_RTOS) && USE_RTOS == 1)
    if (!convertApduStrInHexArray(apdu_str, &apdu_len, apdu, SE05X_MAX_BUF_SIZE_CMD))
#else
    if (!smApduGetArrayBytes(apdu_str, &apdu_len, apdu, SE05X_MAX_BUF_SIZE_CMD))
#endif
    {
		EXIT_STATUS_MSG(IOT_AGENT_FAILURE, "invalid hexstr in [%s]\n", buf);
    }

    resp_to_compare_str = resp_str;
    if (found > 1) {
        // the response CAN be prepended with a star signifying that
        // there can be more characters. ignore those.
        if (resp_str[0] == '*') {
			compare_response = true;
            resp_to_compare_str = &resp_str[1];
        }

		// cast the argument buffer_len, since is externally defined
        smApduGetArrayBytes(resp_to_compare_str, &resp_len, resp, (size_t)SE05X_MAX_BUF_SIZE_RSP * 2);
	}

	FPRINTF("Executing [%s]\n", buf);
	memset(rx, 0, MAX_TX_RX_BUFFER);
	resp_apdu_length = 0;

	if (SM_OK != DoAPDUTxRx(&pSession->s_ctx, apdu, apdu_len, &rx[0], &rlen)) {
		FPRINTF("Received response APDU with error status code\n");
	}

	// fill the response buffer in case will be retrieved from command
	if (rlen > 0)
	{
		resp_apdu_length = (rlen * 2);
		free(resp_apdu_ptr);
		resp_apdu_ptr = (char*)malloc(resp_apdu_length + 1);
		if (!(getRespString(resp_apdu_ptr, rx, rlen)))
		{
			EXIT_STATUS_MSG(IOT_AGENT_FAILURE, "Error in the response buffer decoding\n");
		}
		FPRINTF("Response successfully decoded\n");
	}

	if (compare_response)
	{
		if ((rlen != resp_len) || (memcmp(resp, rx, rlen) != 0))
		{
			EXIT_STATUS_MSG(IOT_AGENT_FAILURE, "Unexpected response for apdu [%s]\n", buf);
		}
	}
	FPRINTF("Success APDU exchange\n");

exit:
	return agent_status;
}

#endif //NXP_IOT_AGENT_HAVE_SSS

#if NXP_IOT_AGENT_HAVE_PSA
// this function sends an APDU to device and checks response
static iot_agent_status_t import_device_cmd(void)
{
	iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
	char key_id_str[MAX_TX_RX_BUFFER] = { 0 };
	char key_type_str[MAX_TX_RX_BUFFER] = { 0 };
	char key_value_str[MAX_TX_RX_BUFFER] = { 0 };
	char key_permitted_alg_str[MAX_TX_RX_BUFFER] = { 0 };
	char key_usage_str[MAX_TX_RX_BUFFER] = { 0 };

	int found = sscanf(start_cmd_ptr, "keydata %s %s %s %s %s", key_id_str, key_type_str, key_permitted_alg_str, key_usage_str, key_value_str);
	IOT_AGENT_DEBUG("Received command: %s \r\n", start_cmd_ptr);
	if (found <= 0) {
		IOT_AGENT_DEBUG("discarding [%s]\n", start_cmd_ptr);
		goto exit;
	}

	agent_status = psa_init_utils_import_cmd(start_cmd_ptr);
	AGENT_SUCCESS_OR_EXIT_MSG("Error in importing the PSA initialization command\n");
exit:
	return agent_status;
}
#endif // NXP_IOT_AGENT_HAVE_PSA

static iot_agent_status_t parse_send_cmd_length_command(nxp_iot_RpcRequest* pRpcRequest)
{
	iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
	ASSERT_OR_EXIT_MSG(pRpcRequest->arg_count == 2U, "Wrong number of arguments in the send command length\n");

	int command_index;
	agent_status = search_argument_per_position(pRpcRequest, RPC_ARGUMENT_POS_SIZE, &command_index);
	AGENT_SUCCESS_OR_EXIT_MSG("Command argument is missing in the packet\n");

	cmd_length = pRpcRequest->arg[command_index].payload.data.uint32_arg;
	start_cmd_ptr = malloc(cmd_length + 1);
	memset(start_cmd_ptr, 0, cmd_length + 1);
	cmd_ptr = start_cmd_ptr;

exit:
	return agent_status;
}

static iot_agent_status_t parse_send_cmd_command(nxp_iot_RpcRequest* pRpcRequest)
{
	iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
	size_t command_length = 0U;
	ASSERT_OR_EXIT_MSG(pRpcRequest->arg_count == 3U, "Wrong number of arguments in the send APDU command\n");

	int command_index;
	agent_status = search_argument_per_position(pRpcRequest, RPC_ARGUMENT_POS_SIZE, &command_index);
	AGENT_SUCCESS_OR_EXIT_MSG("Command argument is missing in the packet\n");

	command_length = pRpcRequest->arg[command_index].payload.data.uint32_arg;

	agent_status = search_argument_per_position(pRpcRequest, RPC_ARGUMENT_POS_DATA, &command_index);
	AGENT_SUCCESS_OR_EXIT_MSG("Command argument is missing in the packet\n");

	ASSERT_OR_EXIT_MSG(((size_t)(cmd_ptr - start_cmd_ptr) + command_length) <= cmd_length, "APDU exceeds the indicated length\n");

	memcpy(cmd_ptr, pRpcRequest->arg[command_index].payload.data.string_arg, command_length);
	if (((size_t)(cmd_ptr - start_cmd_ptr) + command_length) == cmd_length)
	{
#if NXP_IOT_AGENT_HAVE_SSS
		send_apdu_to_device();
#endif
#if NXP_IOT_AGENT_HAVE_PSA
		import_device_cmd();
#endif
		free(start_cmd_ptr);
	}
	else
	{
		cmd_ptr += command_length;
	}
exit:
	return agent_status;
}

static iot_agent_status_t parse_get_string(nxp_iot_RpcRequest* pRpcRequest, char* object_id)
{
	iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
	size_t command_length = 0U;
	ASSERT_OR_EXIT_MSG(pRpcRequest->arg_count == 3U, "Wrong number of arguments in the send APDU command\n");

	int command_index;
	agent_status = search_argument_per_position(pRpcRequest, RPC_ARGUMENT_POS_SIZE, &command_index);
	AGENT_SUCCESS_OR_EXIT_MSG("Command argument is missing in the packet\n");

	command_length = pRpcRequest->arg[command_index].payload.data.uint32_arg;

	agent_status = search_argument_per_position(pRpcRequest, RPC_ARGUMENT_POS_DATA, &command_index);
	AGENT_SUCCESS_OR_EXIT_MSG("Command argument is missing in the packet\n");

	memcpy(object_id, pRpcRequest->arg[command_index].payload.data.string_arg, command_length);

exit:
	return agent_status;
}


static iot_agent_status_t handle_endpoint_request(nxp_iot_RpcRequest* pRpcRequest,
	nxp_iot_RpcResponse* pRpcResponse, iot_agent_context_t *iot_agent_context)
{
	iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
    pb_istream_t istream;
    handle_request_payload_args_t handle_request_args = { 0 };
    handle_request_payload_args_t* handle_request_args_ptr = NULL;
    iot_agent_response_buffer_t response_buffer;
    bool handled_reqest;

	ASSERT_OR_EXIT_MSG(pRpcRequest->arg_count == 2U, "Wrong number of arguments in the handle_endpoint_request command\n");
	ASSERT_OR_EXIT_MSG(pRpcRequest->arg[1].has_payload, "Argument 0 has no payload in the handle_endpoint_request command\n");
	ASSERT_OR_EXIT_MSG(pRpcRequest->arg[1].payload.which_data == nxp_iot_ArgumentPayload_bytes_arg_tag,
		"Argument 0 does not have type bytes in the handle_endpoint_request command\n");

	// Prepare the response.
	pRpcResponse->has_id = true;
	pRpcResponse->id = RPC_ID;
	pRpcResponse->arg_count = 2;
	pRpcResponse->arg[1].has_payload = true;
	pRpcResponse->arg[1].payload.which_data = nxp_iot_ArgumentPayload_bytes_arg_tag;

	// We have all we need in the agent already, let the agent do the dispatching etc...

	// Take the reqyest from the first RPC request argument.
	istream = pb_istream_from_buffer(pRpcRequest->arg[1].payload.data.bytes_arg.bytes,
		(size_t)pRpcRequest->arg[1].payload.data.bytes_arg.size);

	iot_agent_dispatcher_context_t dispatcher_context;
	iot_agent_init_dispatcher(&dispatcher_context, iot_agent_context, NULL, NULL);
	dispatcher_context.successful_crl_verification_done = true;

	// Write the response to the first RPC response argument.
	response_buffer.start = &pRpcResponse->arg[1].payload.data.bytes_arg.bytes[0];
	response_buffer.pos = response_buffer.start;
	response_buffer.remaining = sizeof(pRpcResponse->arg[1].payload.data.bytes_arg.bytes);

	handle_request_args.dispatcher_context = &dispatcher_context;
	handle_request_args.response_buffer = &response_buffer;
	handle_request_args_ptr = &handle_request_args;

	handled_reqest = handle_requests(&istream, nxp_iot_Requests_fields, &handle_request_args_ptr);

	pRpcResponse->arg[1].payload.data.bytes_arg.size = response_buffer.pos - response_buffer.start;

	// Also send back a status in addition to the real payload.
	pRpcResponse->arg[0].has_pos = true;
	pRpcResponse->arg[0].pos = RPC_ARGUMENT_POS_CMD;
	pRpcResponse->arg[0].has_payload = true;
	pRpcResponse->arg[0].payload.which_data = nxp_iot_ArgumentPayload_uint32_arg_tag;
	pRpcResponse->arg[0].payload.data.uint32_arg = handled_reqest ? (uint32_t)RPC_RESPONSE_STATE_SUCCESS : (uint32_t)RPC_RESPONSE_STATE_ERROR;

exit:
	return agent_status;
}

#if NXP_IOT_AGENT_HAVE_SSS
// This function executes the factory reset on the secure element
static iot_agent_status_t execute_factory_reset(ex_sss_boot_ctx_t *pCtx)
{
	iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
	uint8_t factory_reset_key[] = {0xA8U, 0x78U, 0x25U, 0x46U, 0x75U, 0x15U, 0x27U, 0xA4U,
		0xA1U, 0xADU, 0x99U, 0x90U, 0x58U, 0x16U, 0x5DU, 0x6AU};
	sss_status_t status;
	SE_Connect_Ctx_t eraseAuthCtx = {0U};
	sss_se05x_session_t *pSession =
		(sss_se05x_session_t *)&pCtx->session;
	sss_session_t reEnableSession = {0U};
	sss_tunnel_t reEnableTunnel = {0U};
	smStatus_t sw_status;
	Se05xSession_t *pSe05xSession;
	sss_object_t ex_id = {0U};
	SE05x_Result_t objExists = 0;

	eraseAuthCtx.auth.ctx.idobj.pObj = &ex_id;

	if (pCtx->host_ks.session == NULL) {
		status = ex_sss_boot_open_host_session(pCtx);
		if (kStatus_SSS_Success != status) {
			EXIT_STATUS_MSG(IOT_AGENT_FAILURE, "Failed ex_sss_boot_open_host_session\n");
		}
	}

	status = sss_key_object_init(eraseAuthCtx.auth.ctx.idobj.pObj, &pCtx->host_ks);
	if (kStatus_SSS_Success != status) {
		EXIT_STATUS_MSG(IOT_AGENT_FAILURE, "Failed sss_key_object_init\n");
	}
	status = sss_key_object_allocate_handle(eraseAuthCtx.auth.ctx.idobj.pObj,
		MAKE_TEST_ID(__LINE__),
		kSSS_KeyPart_Default,
		kSSS_CipherType_UserID,
		sizeof(factory_reset_key),
		kKeyObject_Mode_Transient);
	if (kStatus_SSS_Success != status) {
		EXIT_STATUS_MSG(IOT_AGENT_FAILURE, "Failed sss_key_object_allocate_handle\n");
	}
	status = sss_key_store_set_key(&pCtx->host_ks,
		eraseAuthCtx.auth.ctx.idobj.pObj,
		factory_reset_key,
		sizeof(factory_reset_key),
		sizeof(factory_reset_key) * 8,
		NULL,
		0U);
	if (kStatus_SSS_Success != status) {
		EXIT_STATUS_MSG(IOT_AGENT_FAILURE, "Failed sss_key_store_set_key\n");
	}

	pSe05xSession = &pSession->s_ctx;

	sw_status = Se05x_API_CheckObjectExists(pSe05xSession, kSE05x_AppletResID_FACTORY_RESET, &objExists);
	if (sw_status == SM_OK && objExists == kSE05x_Result_SUCCESS) {
		IOT_AGENT_WARN("kSE05x_AppletResID_FACTORY_RESET Object already exists");
	}
	else if (sw_status == SM_OK && objExists == kSE05x_Result_FAILURE) {
		sw_status = Se05x_API_WriteUserID(pSe05xSession,
			NULL,
			SE05x_MaxAttemps_NA,
			kSE05x_AppletResID_FACTORY_RESET,
			factory_reset_key,
			sizeof(factory_reset_key),
			kSE05x_AttestationType_AUTH);
		if (SM_OK != sw_status) {
			EXIT_STATUS_MSG(IOT_AGENT_FAILURE, "Error in writing user ID\n");
		}
	}
	else
	{
		EXIT_STATUS_MSG(IOT_AGENT_FAILURE, "Error in opening session ID\n");
	}
	if (sw_status != SM_OK) {
		EXIT_STATUS_MSG(IOT_AGENT_FAILURE, "Error in writing user ID\n");
	}

	if (pSession->s_ctx.authType == kSSS_AuthType_SCP03 || pSession->s_ctx.authType == kSSS_AuthType_AESKey) {
		// UserID inside PlatformSCP
		pSe05xSession = &((sss_se05x_session_t *)&reEnableSession)->s_ctx;
		eraseAuthCtx.tunnelCtx = &reEnableTunnel;
		reEnableTunnel.session = &pCtx->session;
		eraseAuthCtx.connType = kType_SE_Conn_Type_Channel; // pOpenCtx->connType;
		eraseAuthCtx.portName = NULL; // pOpenCtx->portName;
		eraseAuthCtx.auth.authType = kSSS_AuthType_ID;
		eraseAuthCtx.skip_select_applet = 1U;

		status = sss_session_open(&reEnableSession, kType_SSS_SE_SE05x,
			kSE05x_AppletResID_FACTORY_RESET,
			kSSS_ConnectionType_Password, &eraseAuthCtx);
		if (kStatus_SSS_Success != status) {
			EXIT_STATUS_MSG(IOT_AGENT_FAILURE, "Failed sss_session_open\n");
		}
	}
	else
	{
		SE_Connect_Ctx_t* pOpenCtx;
		pOpenCtx = &pCtx->se05x_open_ctx;
		eraseAuthCtx.tunnelCtx = pOpenCtx->tunnelCtx;
		eraseAuthCtx.connType = pOpenCtx->connType;
		eraseAuthCtx.portName = pOpenCtx->portName;
		eraseAuthCtx.auth.authType = kSSS_AuthType_ID;

		iot_agent_session_disconnect(pCtx);
		//sss_session_close(&pCtx->session);
		pSe05xSession = &pSession->s_ctx;

		status = sss_session_open(&pCtx->session, kType_SSS_SE_SE05x,
			kSE05x_AppletResID_FACTORY_RESET,
			kSSS_ConnectionType_Password, &eraseAuthCtx);

	}

	if (kStatus_SSS_Success != status) {
		EXIT_STATUS_MSG(IOT_AGENT_FAILURE, "Failed sss_session_open\n");
	}

	sw_status = Se05x_API_DeleteAll(pSe05xSession);
	if (SM_OK != sw_status) {
		EXIT_STATUS_MSG(IOT_AGENT_FAILURE, "Failed Se05x_API_DeleteAll\n");
	}
	else
	{
		IOT_AGENT_INFO("Since Se05x_API_DeleteAll was successful, subsequent calls may fail.");
	}

	SM_Close(pSession->s_ctx.conn_ctx, 0U);
	//SM_Close(NULL, 0);
	/* Foreful over-ride, not a valid session */
	pSession->subsystem = kType_SSS_SubSystem_NONE;

	sss_key_object_free(eraseAuthCtx.auth.ctx.idobj.pObj);

	agent_status = iot_agent_session_connect(pCtx);
exit:
	return agent_status;
}

// This function creates the EC Curve inside the device
static iot_agent_status_t createCurve(sss_se05x_session_t *pSession, uint32_t curve_id)
{
	iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
	smStatus_t status = SM_OK;

	switch (curve_id) {
#if SSS_HAVE_EC_NIST_192
	case kSE05x_ECCurve_NIST_P192:
		status = Se05x_API_CreateCurve_prime192v1(&pSession->s_ctx, curve_id);
		break;
#endif
#if SSS_HAVE_EC_NIST_224
	case kSE05x_ECCurve_NIST_P224:
		status = Se05x_API_CreateCurve_secp224r1(&pSession->s_ctx, curve_id);
		break;
#endif
	case kSE05x_ECCurve_NIST_P256:
		status = Se05x_API_CreateCurve_prime256v1(&pSession->s_ctx, curve_id);
		break;
	case kSE05x_ECCurve_NIST_P384:
		status = Se05x_API_CreateCurve_secp384r1(&pSession->s_ctx, curve_id);
		break;
#if SSS_HAVE_EC_NIST_521
	case kSE05x_ECCurve_NIST_P521:
		status = Se05x_API_CreateCurve_secp521r1(&pSession->s_ctx, curve_id);
		break;
#endif
#if SSS_HAVE_EC_BP
	case kSE05x_ECCurve_Brainpool160:
		status = Se05x_API_CreateCurve_brainpoolP160r1(&pSession->s_ctx, curve_id);
		break;
	case kSE05x_ECCurve_Brainpool192:
		status = Se05x_API_CreateCurve_brainpoolP192r1(&pSession->s_ctx, curve_id);
		break;
	case kSE05x_ECCurve_Brainpool224:
		status = Se05x_API_CreateCurve_brainpoolP224r1(&pSession->s_ctx, curve_id);
		break;
	case kSE05x_ECCurve_Brainpool256:
		status = Se05x_API_CreateCurve_brainpoolP256r1(&pSession->s_ctx, curve_id);
		break;
	case kSE05x_ECCurve_Brainpool320:
		status = Se05x_API_CreateCurve_brainpoolP320r1(&pSession->s_ctx, curve_id);
		break;
	case kSE05x_ECCurve_Brainpool384:
		status = Se05x_API_CreateCurve_brainpoolP384r1(&pSession->s_ctx, curve_id);
		break;
	case kSE05x_ECCurve_Brainpool512:
		status = Se05x_API_CreateCurve_brainpoolP512r1(&pSession->s_ctx, curve_id);
		break;
#endif
#if SSS_HAVE_EC_NIST_K
	case kSE05x_ECCurve_Secp160k1:
		status = Se05x_API_CreateCurve_secp160k1(&pSession->s_ctx, curve_id);
		break;
	case kSE05x_ECCurve_Secp192k1:
		status = Se05x_API_CreateCurve_secp192k1(&pSession->s_ctx, curve_id);
		break;
	case kSE05x_ECCurve_Secp224k1:
		status = Se05x_API_CreateCurve_secp224k1(&pSession->s_ctx, curve_id);
		break;
	case kSE05x_ECCurve_Secp256k1:
		status = Se05x_API_CreateCurve_secp256k1(&pSession->s_ctx, curve_id);
		break;
#endif
	default:
		break;
	}
	if (status != SM_OK)
	{
		EXIT_STATUS_MSG(IOT_AGENT_FAILURE, "Error in curve creation\n");
	}
exit:
	return agent_status;
}

// This function parses the set ECC curve command
static iot_agent_status_t parse_set_ecc_curve_command (nxp_iot_RpcRequest* pRpcRequest, sss_se05x_session_t *pSession)
{
	iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
	uint8_t curve_list[kSE05x_ECCurve_Total_Weierstrass_Curves] = {0U};
	size_t curve_list_len = sizeof(curve_list);
	uint8_t curve_list_tlv_array[kSE05x_ECCurve_Total_Weierstrass_Curves + 4];
	size_t resp_len = 0U;
	int command_index = 0;
	size_t rspIndex = 0U;

	ASSERT_OR_EXIT_MSG(pRpcRequest->arg_count == 3U, "Wrong number of arguments in the send APDU command\n");

	agent_status = search_argument_per_position(pRpcRequest, RPC_ARGUMENT_POS_SIZE, &command_index);
	AGENT_SUCCESS_OR_EXIT_MSG("Command argument is missing in the packet\n");

	agent_status = search_argument_per_position(pRpcRequest, RPC_ARGUMENT_POS_DATA, &command_index);
	AGENT_SUCCESS_OR_EXIT_MSG("Command argument is missing in the packet\n");
	// parse the received TLV structure

#if (defined(AX_EMBEDDED) && defined(USE_RTOS) && USE_RTOS == 1)
    if (!(convertApduStrInHexArray(pRpcRequest->arg[command_index].payload.data.string_arg, &resp_len, curve_list_tlv_array, sizeof(curve_list_tlv_array))))
#else
    if (!(smApduGetArrayBytes(pRpcRequest->arg[command_index].payload.data.string_arg, &resp_len, curve_list_tlv_array, sizeof(curve_list_tlv_array))))
#endif
	{
		EXIT_STATUS_MSG(IOT_AGENT_FAILURE, "Error in the EC Curve string\n");
	}

	if (tlvGet_u8buf(curve_list_tlv_array, &rspIndex, resp_len, kSE05x_TAG_1, curve_list, &curve_list_len))
	{
		EXIT_STATUS_MSG(IOT_AGENT_FAILURE, "Error in the EC Curve string\n");
	}

	for (int i = 0; i < kSE05x_ECCurve_Total_Weierstrass_Curves; i++)
	{
		if (curve_list[i] == kSE05x_SetIndicator_SET)
		{
			agent_status = createCurve(pSession, (uint32_t)(i + 1));
			AGENT_SUCCESS_OR_EXIT_MSG("Error in curve creation\n");
		}
	}

exit:
	return agent_status;
}

static iot_agent_status_t execute_connect_to_services(iot_agent_context_t *iot_agent_context)
{
	iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
	size_t number_of_services = 0U;
	nxp_iot_ServiceDescriptor service_descriptor = nxp_iot_ServiceDescriptor_init_default;

	number_of_services = iot_agent_get_number_of_services(iot_agent_context);
	AGENT_SUCCESS_OR_EXIT();

	for (size_t i = 0U; i < number_of_services; i++)
	{
		agent_status = iot_agent_select_service_by_index(iot_agent_context, i, &service_descriptor);
		AGENT_SUCCESS_OR_EXIT();

		agent_status = iot_agent_verify_mqtt_connection_for_service(iot_agent_context, &service_descriptor);
#if NXP_IOT_AGENT_HAVE_HOSTCRYPTO_OPENSSL
		write_log(TEST_LOG_ID_CONNECTED_SERVICE, "{ service_id: '%" PRIu64 "', status: '%d' }",
			service_descriptor.identifier, agent_status);
#endif
#if NXP_IOT_AGENT_HAVE_HOSTCRYPTO_MBEDTLS
		write_log(TEST_LOG_ID_CONNECTED_SERVICE, "{ service_id: '%d', status: '%d' }",
			(uint32_t) service_descriptor.identifier, agent_status);
#endif
		AGENT_SUCCESS_OR_EXIT();

		agent_status = iot_agent_cleanup_mqtt_config_files();
		AGENT_SUCCESS_OR_EXIT();
	}
exit:
	iot_agent_free_service_descriptor(&service_descriptor);
	return agent_status;
}
#endif //NXP_IOT_AGENT_HAVE_SSS


#if ((NXP_IOT_AGENT_HAVE_HOSTCRYPTO_OPENSSL) || (AX_EMBEDDED && defined(USE_RTOS) && USE_RTOS == 1))
static iot_agent_status_t execute_cos_over_rtp_connection(iot_agent_context_t *iot_agent_context, char* serviceDescriptorId) {
	iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
	nxp_iot_ServiceDescriptor service_descriptor = nxp_iot_ServiceDescriptor_init_default;
	iot_agent_keystore_t* keystore = NULL;
	sss_key_store_t* sss_keystore = NULL;
	uint32_t keystore_id = EDGELOCK2GO_KEYSTORE_ID;
	uint8_t binary[COS_OVER_RTP_CERT_SIZE];
	size_t binary_len = sizeof(binary);
	uint32_t binary_id = 0U;
	sss_status_t sss_status;
	sss_object_t certObj = { 0 };

	size_t cert_lenBits = (binary_len) * 8U;

#if defined(_WIN32) && (_WIN32 == 1)
	binary_id = (uint32_t)_strtoi64(serviceDescriptorId, NULL, 0);
#else
	binary_id = (uint32_t)strtoull(serviceDescriptorId, NULL, 0);
#endif
	agent_status = iot_agent_get_keystore_by_id(iot_agent_context, keystore_id, &keystore);
	AGENT_SUCCESS_OR_EXIT();

	agent_status = iot_agent_keystore_sss_se05x_get_sss_key_store(keystore->context, &sss_keystore);
	AGENT_SUCCESS_OR_EXIT_MSG("iot_agent_keystore_sss_se05x_get_sss_key_store failed: 0x%08x", agent_status);

	sss_status = sss_key_object_init(&certObj, sss_keystore);
	SSS_SUCCESS_OR_EXIT_MSG("sss_key_object_init failed: 0x%08x.", sss_status);

	sss_status = sss_key_object_get_handle(&certObj, binary_id);
	SSS_SUCCESS_OR_EXIT_MSG("sss_key_object_get_handle failed: 0x%08x [object id: 0x%08x].", sss_status, binary_id);

	sss_status = sss_key_store_get_key(sss_keystore, &certObj, (uint8_t*)binary, &binary_len, &cert_lenBits);
	SSS_SUCCESS_OR_EXIT_MSG("sss_key_store_get_key failed: 0x%08x [object id: 0x%08x].", sss_status, binary_id);

	pb_istream_t stream = pb_istream_from_buffer(binary, binary_len);

	bool pb_status = pb_decode_delimited(&stream, nxp_iot_ServiceDescriptor_fields, &service_descriptor);
	ASSERT_OR_EXIT_MSG(pb_status == true, "pb_decode_delimited failed.");

	if (service_descriptor.service_type == nxp_iot_ServiceType_AWSSERVICE)
	{
		if (strcmp(service_descriptor.client_id, "") == 0)
		{
			service_descriptor.client_id = malloc(COMMON_NAME_MAX_SIZE);
			memset(service_descriptor.client_id, 0, COMMON_NAME_MAX_SIZE);
			agent_status = iot_agent_utils_get_certificate_common_name(iot_agent_context, &service_descriptor, service_descriptor.client_id, COMMON_NAME_MAX_SIZE);
			AGENT_SUCCESS_OR_EXIT();
		}

		// in AWS auto registration, the first connection will always result in a fail, the lambda function
		// on AWS will register the device certificate; the second connection will work
		agent_status = iot_agent_verify_mqtt_connection_cos_over_rtp(iot_agent_context, &service_descriptor);
		agent_status = iot_agent_verify_mqtt_connection_cos_over_rtp(iot_agent_context, &service_descriptor);
		AGENT_SUCCESS_OR_EXIT();
	}
	else if (service_descriptor.service_type == nxp_iot_ServiceType_AZURESERVICE)
	{
		if (strcmp(service_descriptor.azure_registration_id, "") == 0)
		{
			service_descriptor.azure_registration_id = malloc(COMMON_NAME_MAX_SIZE);
			memset(service_descriptor.azure_registration_id, 0, COMMON_NAME_MAX_SIZE);
			agent_status = iot_agent_utils_get_certificate_common_name(iot_agent_context, &service_descriptor, service_descriptor.azure_registration_id, COMMON_NAME_MAX_SIZE);
			AGENT_SUCCESS_OR_EXIT();
		}
		agent_status = iot_agent_verify_mqtt_connection_cos_over_rtp(iot_agent_context, &service_descriptor);
		AGENT_SUCCESS_OR_EXIT();
	}

exit:
#if NXP_IOT_AGENT_HAVE_HOSTCRYPTO_OPENSSL
	write_log(TEST_LOG_ID_CONNECTED_SERVICE, "{ service_id: '%" PRIu64 "', status: '%d' }",
		service_descriptor.identifier, agent_status);
#endif
#if NXP_IOT_AGENT_HAVE_HOSTCRYPTO_MBEDTLS
	write_log(TEST_LOG_ID_CONNECTED_SERVICE, "{ service_id: '%d', status: '%d' }",
		(uint32_t)service_descriptor.identifier, agent_status);
#endif
	iot_agent_free_service_descriptor(&service_descriptor);
	return agent_status;
}
#endif


#if NXP_IOT_AGENT_HAVE_PSA
typedef struct psa_api_context {
	uint32_t object_id;
	psa_algorithm_t algorithm;
	uint8_t* input;
	size_t input_length;
	uint8_t* output;
	size_t output_length;
	uint8_t* additional;
	size_t additional_length;
}psa_api_context_t;

typedef iot_agent_status_t (*execute_psa_api_t)(psa_api_context_t* psa_api_context);

static void build_rpc_response_byte_array(nxp_iot_RpcResponse* pRpcResponse, uint8_t* buffer, size_t buffer_size) {
	nxp_iot_Argument outArg0 = nxp_iot_Argument_init_default;
	nxp_iot_Argument outArg1 = nxp_iot_Argument_init_default;

	// build the response, the first argument is setting up the state
	pRpcResponse->has_id = true;
	pRpcResponse->id = RPC_ID;
	pRpcResponse->arg_count = 2U;

	outArg0.has_pos = true;
	outArg0.pos = RPC_ARGUMENT_POS_CMD;
	outArg0.has_payload = true;
	outArg0.payload.which_data = nxp_iot_ArgumentPayload_uint32_arg_tag;
	outArg0.payload.data.uint32_arg = (uint32_t)RPC_RESPONSE_STATE_SUCCESS;
	pRpcResponse->arg[0] = outArg0;

	outArg1.has_pos = true;
	outArg1.pos = RPC_ARGUMENT_POS_CMD + 1;
	outArg1.has_payload = true;
	outArg1.payload.which_data = nxp_iot_ArgumentPayload_bytes_arg_tag;
	outArg1.payload.data.bytes_arg.size = (uint32_t)buffer_size;
	memcpy(outArg1.payload.data.bytes_arg.bytes, buffer, buffer_size);
	pRpcResponse->arg[1] = outArg1;
}

static iot_agent_status_t execute_psa_cipher(psa_api_context_t* psa_api_context) {
	iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
	psa_status_t psa_status = PSA_SUCCESS;
	psa_cipher_operation_t cipher_operation = psa_cipher_operation_init();
	psa_status = psa_cipher_encrypt_setup(&cipher_operation, psa_api_context->object_id, psa_api_context->algorithm);
	PSA_SUCCESS_OR_EXIT_MSG("Error in cipher setup");
	if ((psa_api_context->additional != NULL) && (psa_api_context->additional_length != 0U)) {
		psa_status = psa_cipher_set_iv(&cipher_operation, psa_api_context->additional, psa_api_context->additional_length);
		PSA_SUCCESS_OR_EXIT_MSG("Error in setting IV");
	}
	psa_status = psa_cipher_update(&cipher_operation,
		psa_api_context->input,
		psa_api_context->input_length,
		psa_api_context->output,
		psa_api_context->output_length,
		&psa_api_context->output_length);
	PSA_SUCCESS_OR_EXIT_MSG("Error in cipher update");
exit:
	return agent_status;
}

static iot_agent_status_t execute_psa_sign(psa_api_context_t* psa_api_context) {
	iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
	psa_status_t psa_status = PSA_SUCCESS;

	psa_status = psa_sign_hash(psa_api_context->object_id,
		psa_api_context->algorithm,
		psa_api_context->input,
		psa_api_context->input_length,
		psa_api_context->output,
		psa_api_context->output_length,
		&psa_api_context->output_length);
	PSA_SUCCESS_OR_EXIT_MSG("Error in signing operation");
exit:
	return agent_status;
}

static iot_agent_status_t execute_psa_hash_and_sign(psa_api_context_t* psa_api_context) {
	iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
	psa_status_t psa_status = PSA_SUCCESS;
	psa_hash_operation_t operation = PSA_HASH_OPERATION_INIT;
	uint8_t hash[MAX_TX_RX_BUFFER] = {0U};
	size_t hash_length = 0U;

	psa_status = psa_hash_setup(&operation,
		PSA_ALG_SIGN_GET_HASH(psa_api_context->algorithm));
	PSA_SUCCESS_OR_EXIT_MSG("Error in hash setup");

	psa_status = psa_hash_update(&operation,
		psa_api_context->input,
		psa_api_context->input_length);
	PSA_SUCCESS_OR_EXIT_MSG("Error in hash update");

	psa_status = psa_hash_finish(&operation,
		hash,
		MAX_TX_RX_BUFFER,
		&hash_length);
	PSA_SUCCESS_OR_EXIT_MSG("Error in hash finish");

	psa_status = psa_sign_hash(psa_api_context->object_id,
		psa_api_context->algorithm,
		hash,
		hash_length,
		psa_api_context->output,
		psa_api_context->output_length,
		&psa_api_context->output_length);
	PSA_SUCCESS_OR_EXIT_MSG("Error in verify operation");
exit:
	return agent_status;
}

static iot_agent_status_t execute_psa_verify(psa_api_context_t* psa_api_context) {
	iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
	psa_status_t psa_status = PSA_SUCCESS;
	psa_api_context->output_length = 2;
	*psa_api_context->output = 0x90;
	*(psa_api_context->output + 1) = 0x00;
	psa_status = psa_verify_hash(psa_api_context->object_id,
		psa_api_context->algorithm,
		psa_api_context->input,
		psa_api_context->input_length,
		psa_api_context->additional,
		psa_api_context->additional_length);
	PSA_SUCCESS_OR_EXIT_MSG("Error in signing operation");
exit:
	return agent_status;
}

static iot_agent_status_t execute_psa_hash_and_verify(psa_api_context_t* psa_api_context) {
	iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
	psa_status_t psa_status = PSA_SUCCESS;
	psa_hash_operation_t operation = PSA_HASH_OPERATION_INIT;
	uint8_t hash[MAX_TX_RX_BUFFER] = { 0U };
	size_t hash_length = 0U;

	psa_api_context->output_length = 2;
	*psa_api_context->output = 0x90;
	*(psa_api_context->output + 1) = 0x00;

	psa_status = psa_hash_setup(&operation,
		PSA_ALG_SIGN_GET_HASH(psa_api_context->algorithm));
	PSA_SUCCESS_OR_EXIT_MSG("Error in hash setup");

	psa_status = psa_hash_update(&operation,
		psa_api_context->input,
		psa_api_context->input_length);
	PSA_SUCCESS_OR_EXIT_MSG("Error in hash update");

	psa_status = psa_hash_finish(&operation,
		hash,
		MAX_TX_RX_BUFFER,
		&hash_length);
	PSA_SUCCESS_OR_EXIT_MSG("Error in hash finish");

	psa_status = psa_verify_hash(psa_api_context->object_id,
		psa_api_context->algorithm,
		hash,
		hash_length,
		psa_api_context->additional,
		psa_api_context->additional_length);
	PSA_SUCCESS_OR_EXIT_MSG("Error in verify operation");
exit:
	return agent_status;
}

static iot_agent_status_t execute_psa_export(psa_api_context_t* psa_api_context) {
	iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
	psa_status_t psa_status = PSA_SUCCESS;
	uint8_t* key = malloc(MAX_PSA_KEY_SIZE);
	size_t key_size = 0U;

	// the offset and length are included in the algorithm variable
	size_t packet_offset = (psa_api_context->algorithm & 0x0000FFFF);
	size_t packet_length = (psa_api_context->algorithm & 0xFFFF0000) >> 16;

	psa_status = psa_export_key(psa_api_context->object_id,
		key,
		MAX_PSA_KEY_SIZE,
		&key_size);
	PSA_SUCCESS_OR_EXIT_MSG("Error in export");
	memcpy(psa_api_context->output, key+packet_offset, packet_length);
	psa_api_context->output_length = packet_length;
exit:
	free(key);
	return agent_status;
}

static iot_agent_status_t execute_psa_mac_sign(psa_api_context_t* psa_api_context) {
	iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
	psa_status_t psa_status = PSA_SUCCESS;
	psa_mac_operation_t operation = PSA_MAC_OPERATION_INIT;

	psa_status = psa_mac_sign_setup(&operation,
		psa_api_context->object_id,
		psa_api_context->algorithm);
	PSA_SUCCESS_OR_EXIT_MSG("Error in MAC sign");

	psa_status = psa_mac_update(&operation,
		psa_api_context->input,
		psa_api_context->input_length);
	PSA_SUCCESS_OR_EXIT_MSG("Error in MAC update");

	psa_status = psa_mac_sign_finish(&operation,
		psa_api_context->output,
		MAX_TX_RX_BUFFER,
		&psa_api_context->output_length);
	PSA_SUCCESS_OR_EXIT_MSG("Error in MAC sign finish");
exit:
	return agent_status;
}

static iot_agent_status_t execute_psa_raw_key_agreement(psa_api_context_t* psa_api_context) {
	iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
	psa_status_t psa_status = PSA_SUCCESS;

	psa_status = psa_raw_key_agreement(psa_api_context->algorithm,
		psa_api_context->object_id,
		psa_api_context->input,
		psa_api_context->input_length,
		psa_api_context->output,
		psa_api_context->output_length,
		&psa_api_context->output_length);
	PSA_SUCCESS_OR_EXIT_MSG("Error in key agreement");
exit:
	return agent_status;
}

static iot_agent_status_t execute_psa_import_bin(psa_api_context_t* psa_api_context) {
	iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
	psa_status_t psa_status = PSA_SUCCESS;
	psa_key_attributes_t attributes = {0U};
	mbedtls_svc_key_id_t key = 0U;

	psa_set_key_usage_flags(&attributes, 0);
	psa_set_key_algorithm(&attributes, psa_api_context->algorithm);
	psa_set_key_type(&attributes, PSA_KEY_TYPE_RAW_DATA);
	psa_set_key_bits(&attributes, psa_api_context->input_length * 8);
	psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_PERSISTENT);
	psa_set_key_id(&attributes, psa_api_context->object_id);

	psa_status = psa_import_key(&attributes,
		psa_api_context->input,
		psa_api_context->input_length,
		&key);
	if (psa_status == PSA_ERROR_ALREADY_EXISTS) {
		// delete the key and re-import it if already exist
		psa_status = psa_destroy_key(psa_get_key_id(&attributes));
		PSA_SUCCESS_OR_EXIT_MSG("Error in destroying the key object");
		psa_status = psa_import_key(&attributes, psa_api_context->input, psa_api_context->input_length, &key);
		PSA_SUCCESS_OR_EXIT_MSG("Error in importing the client key");
	}
	else {
		ASSERT_OR_EXIT_MSG(psa_status == PSA_SUCCESS,
			"Error in importing the client key");
	}

	PSA_SUCCESS_OR_EXIT_MSG("Error in key import");
exit:
	return agent_status;
}


execute_psa_api_t execute_psa_api_array[] = {execute_psa_cipher,
	execute_psa_sign,
	execute_psa_hash_and_sign,
	execute_psa_verify,
	execute_psa_hash_and_verify,
	execute_psa_export,
	execute_psa_mac_sign,
	execute_psa_raw_key_agreement,
	execute_psa_import_bin
};

static iot_agent_status_t parse_execute_psa_api(nxp_iot_RpcRequest* pRpcRequest, nxp_iot_RpcResponse* pRpcResponse) {
	iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
	psa_api_context_t psa_api_context = { 0U };
	uint32_t operation_id = 0U;

	ASSERT_OR_EXIT_MSG(((pRpcRequest->arg_count >=4U) || (pRpcRequest->arg_count <= 6U)), "Wrong number of arguments in the handle_endpoint_request command\n");

	ASSERT_OR_EXIT_MSG(pRpcRequest->arg[RPC_ARGUMENT_POS_PSA_OPERATION].has_payload, "Argument PSA_OPERATION has no payload in the handle_endpoint_request command\n");
	ASSERT_OR_EXIT_MSG(pRpcRequest->arg[RPC_ARGUMENT_POS_PSA_OPERATION].payload.which_data == nxp_iot_ArgumentPayload_uint32_arg_tag,
		"Argument PSA_OPERATION does not have type uint32_t in the handle_endpoint_request command\n");
	operation_id = pRpcRequest->arg[RPC_ARGUMENT_POS_PSA_OPERATION].payload.data.uint32_arg;

	ASSERT_OR_EXIT_MSG(pRpcRequest->arg[RPC_ARGUMENT_POS_PSA_OBJECT_ID].has_payload, "Argument POS_PSA_OBJECT_ID has no payload in the handle_endpoint_request command\n");
	ASSERT_OR_EXIT_MSG(pRpcRequest->arg[RPC_ARGUMENT_POS_PSA_OBJECT_ID].payload.which_data == nxp_iot_ArgumentPayload_uint32_arg_tag,
		"Argument POS_PSA_OBJECT_ID does not have type uint32_t in the handle_endpoint_request command\n");
	psa_api_context.object_id = pRpcRequest->arg[RPC_ARGUMENT_POS_PSA_OBJECT_ID].payload.data.uint32_arg;

	ASSERT_OR_EXIT_MSG(pRpcRequest->arg[RPC_ARGUMENT_POS_PSA_ALGORITHM].has_payload, "Argument PSA_ALGORITHM has no payload in the handle_endpoint_request command\n");
	ASSERT_OR_EXIT_MSG(pRpcRequest->arg[RPC_ARGUMENT_POS_PSA_ALGORITHM].payload.which_data == nxp_iot_ArgumentPayload_uint32_arg_tag,
		"Argument PSA_ALGORITHM does not have type uint32_t in the handle_endpoint_request command\n");
	psa_api_context.algorithm = pRpcRequest->arg[RPC_ARGUMENT_POS_PSA_ALGORITHM].payload.data.uint32_arg;

	if (pRpcRequest->arg_count >= 5U) {
		ASSERT_OR_EXIT_MSG(pRpcRequest->arg[RPC_ARGUMENT_POS_PSA_INPUT].has_payload, "Argument PSA_INPUT has no payload in the handle_endpoint_request command\n");
		ASSERT_OR_EXIT_MSG(pRpcRequest->arg[RPC_ARGUMENT_POS_PSA_INPUT].payload.which_data == nxp_iot_ArgumentPayload_bytes_arg_tag,
			"Argument PSA_INPUT does not have type bytes in the handle_endpoint_request command\n");
		psa_api_context.input_length = pRpcRequest->arg[RPC_ARGUMENT_POS_PSA_INPUT].payload.data.bytes_arg.size;
		psa_api_context.input = malloc(psa_api_context.input_length);
		memcpy(psa_api_context.input, pRpcRequest->arg[RPC_ARGUMENT_POS_PSA_INPUT].payload.data.bytes_arg.bytes, psa_api_context.input_length);

		if (pRpcRequest->arg_count >= 6U) {
			ASSERT_OR_EXIT_MSG(pRpcRequest->arg[RPC_ARGUMENT_POS_PSA_ADDITIONAL].has_payload, "Argument PSA_ADDITIONAL has no payload in the handle_endpoint_request command\n");
			ASSERT_OR_EXIT_MSG(pRpcRequest->arg[RPC_ARGUMENT_POS_PSA_ADDITIONAL].payload.which_data == nxp_iot_ArgumentPayload_bytes_arg_tag,
				"Argument PSA_ADDITIONAL does not have type bytes in the handle_endpoint_request command\n");
			psa_api_context.additional_length = pRpcRequest->arg[RPC_ARGUMENT_POS_PSA_ADDITIONAL].payload.data.bytes_arg.size;
			psa_api_context.additional = malloc(psa_api_context.additional_length);
			memcpy(psa_api_context.additional, pRpcRequest->arg[RPC_ARGUMENT_POS_PSA_ADDITIONAL].payload.data.bytes_arg.bytes, psa_api_context.additional_length);
		}
	}

	psa_api_context.output = malloc(MAX_TX_RX_BUFFER);
	memset(psa_api_context.output, 0U, MAX_TX_RX_BUFFER);
	psa_api_context.output_length = MAX_TX_RX_BUFFER;

	if (execute_psa_api_array[operation_id](&psa_api_context) == IOT_AGENT_SUCCESS) {
		build_rpc_response_byte_array(pRpcResponse, psa_api_context.output, psa_api_context.output_length);
	}
	else {
		build_rpc_response_status(pRpcResponse, RPC_RESPONSE_STATE_ERROR);
	}
exit:
	free(psa_api_context.input);
	free(psa_api_context.output);
	free(psa_api_context.additional);
	return agent_status;
}

static iot_agent_status_t parse_inject_claim_code(nxp_iot_RpcRequest* pRpcRequest, nxp_iot_RpcResponse* pRpcResponse) {
	iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
	char* claim_code = NULL;
	uint8_t* public_key = NULL;
	size_t public_key_size = 0U;

	ASSERT_OR_EXIT_MSG((pRpcRequest->arg_count == 3U), "Wrong number of arguments in the handle_endpoint_request command\n");

	ASSERT_OR_EXIT_MSG(pRpcRequest->arg[1].has_payload, "Argument 1 has no payload in the handle_endpoint_request command\n");
	ASSERT_OR_EXIT_MSG(pRpcRequest->arg[1].payload.which_data == nxp_iot_ArgumentPayload_bytes_arg_tag,
		"Argument 3 does not have type bytes in the handle_endpoint_request command\n");
	claim_code = malloc(pRpcRequest->arg[1].payload.data.bytes_arg.size + 1);
	memset(claim_code, 0, pRpcRequest->arg[1].payload.data.bytes_arg.size + 1);
	memcpy(claim_code, pRpcRequest->arg[1].payload.data.bytes_arg.bytes, pRpcRequest->arg[1].payload.data.bytes_arg.size);

	ASSERT_OR_EXIT_MSG(pRpcRequest->arg[2].has_payload, "Argument 0 has no payload in the handle_endpoint_request command\n");
	ASSERT_OR_EXIT_MSG(pRpcRequest->arg[2].payload.which_data == nxp_iot_ArgumentPayload_bytes_arg_tag,
		"Argument 5 does not have type bytes in the handle_endpoint_request command\n");
	public_key_size = pRpcRequest->arg[2].payload.data.bytes_arg.size;
	public_key = malloc(public_key_size);
	memcpy(public_key, pRpcRequest->arg[2].payload.data.bytes_arg.bytes, public_key_size);

	if (iot_agent_claimcode_encrypt_and_import(claim_code, public_key, public_key_size) == IOT_AGENT_SUCCESS) {
		build_rpc_response_status(pRpcResponse, RPC_RESPONSE_STATE_SUCCESS);
	}
	else {
		build_rpc_response_status(pRpcResponse, RPC_RESPONSE_STATE_ERROR);
	}
exit:
	free(claim_code);
	free(public_key);
	return agent_status;
}

#endif
static void write_status_report_log(const nxp_iot_UpdateStatusReport* status_report) {
	char buffer[8 * 1024];
	const size_t buffer_sz = sizeof(buffer);
	char* start_buffer_ptr = &buffer[0];
	char* buffer_ptr = &buffer[0];

	if (status_report->has_status) {
		buffer_ptr += snprintf(buffer_ptr, buffer_sz - (size_t)(buffer_ptr - start_buffer_ptr), "{ status: %d", status_report->status);
		if (status_report->has_claimStatus) {
			buffer_ptr += snprintf(buffer_ptr, buffer_sz - (size_t)(buffer_ptr - start_buffer_ptr), ", claim_status: { status: %d, details: [", status_report->claimStatus.status);
			for (size_t i = 0U; i < status_report->claimStatus.details_count; i++) {
				buffer_ptr += snprintf(buffer_ptr, buffer_sz - (size_t)(buffer_ptr - start_buffer_ptr), "%s { endpoint_id: %d, status: %d }",
					i == 0U ? "" : ",",
					status_report->claimStatus.details[i].endpointId, status_report->claimStatus.details[i].status);
			}
			buffer_ptr += snprintf(buffer_ptr, buffer_sz - (size_t)(buffer_ptr - start_buffer_ptr), " ] }");
		}

		if (status_report->has_rtpStatus) {
			buffer_ptr += snprintf(buffer_ptr, buffer_sz - (size_t)(buffer_ptr - start_buffer_ptr), ", rtp_status: { status: %d, details: [", status_report->rtpStatus.status);
			for (size_t i = 0U; i < status_report->rtpStatus.details_count; i++) {
				buffer_ptr += snprintf(buffer_ptr, buffer_sz - (size_t)(buffer_ptr - start_buffer_ptr), "%s { endpoint_id: %d, object_id: %d, status: %d }",
					i == 0U ? "" : ",",
					status_report->rtpStatus.details[i].endpointId, status_report->rtpStatus.details[i].objectId, status_report->rtpStatus.details[i].status);
			}
			buffer_ptr += snprintf(buffer_ptr, buffer_sz - (size_t)(buffer_ptr - start_buffer_ptr), " ] }");
		}

		if (status_report->has_cspStatus) {
			buffer_ptr += snprintf(buffer_ptr, buffer_sz - (size_t)(buffer_ptr - start_buffer_ptr), ", csp_status: { status: %d, details: [ ", status_report->cspStatus.status);
			for (size_t i = 0U; i < status_report->cspStatus.details_count; i++) {
#if NXP_IOT_AGENT_HAVE_HOSTCRYPTO_OPENSSL
				buffer_ptr += snprintf(buffer_ptr, buffer_sz - (size_t)(buffer_ptr - start_buffer_ptr), "%s { endpoint_id: %d, service_id: %" PRIu64 ", status: %d }",
					i == 0U ? "" : ",",
					status_report->cspStatus.details[i].endpointId, status_report->cspStatus.details[i].serviceId, status_report->cspStatus.details[i].status);
#endif
#if NXP_IOT_AGENT_HAVE_HOSTCRYPTO_MBEDTLS
				buffer_ptr += snprintf(buffer_ptr, buffer_sz - (size_t)(buffer_ptr - start_buffer_ptr), "%s { endpoint_id: %d, service_id: %d, status: %d }",
					i == 0U ? "" : ",",
					status_report->cspStatus.details[i].endpointId, (uint32_t)status_report->cspStatus.details[i].serviceId, status_report->cspStatus.details[i].status);
#endif
			}
			buffer_ptr += snprintf(buffer_ptr, buffer_sz - (size_t)(buffer_ptr - start_buffer_ptr), " ] }");
		}

		if (status_report->has_correlationId) {
			buffer_ptr += snprintf(buffer_ptr, buffer_sz - (size_t)(buffer_ptr - start_buffer_ptr), ", correlation_id: %s", status_report->correlationId);
		}

		buffer_ptr += snprintf(buffer_ptr, buffer_sz - (size_t)(buffer_ptr - start_buffer_ptr), " }");

	}
	write_log(TEST_LOG_ID_STATUS_REPORT, "%s", buffer);
}

static iot_agent_status_t write_edgelock2go_datastore_from_env(iot_agent_keystore_t *keystore,
	iot_agent_datastore_t* datastore)
{
    iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
    const char *hostname = EDGELOCK2GO_HOSTNAME;
    char *hostname_local = NULL;
    uint32_t port = EDGELOCK2GO_PORT;
	char* edgelock2go_hostname_env = NULL;
	char* edgelock2go_port_env = NULL;

	ASSERT_OR_EXIT_MSG(keystore != NULL, "keystore is NULL.");
	ASSERT_OR_EXIT_MSG(datastore != NULL, "datastore is NULL.");

#if defined(_WIN32) || defined(_WIN64)
	size_t edgelock2go_hostname_env_size = 0U;
	ASSERT_OR_EXIT_MSG(_dupenv_s(&edgelock2go_hostname_env, &edgelock2go_hostname_env_size, "IOT_AGENT_TEST_EDGELOCK2GO_HOSTNAME") == 0, "Error in getting environmental variable");
#else
	edgelock2go_hostname_env = getenv("IOT_AGENT_TEST_EDGELOCK2GO_HOSTNAME");
#endif
    if (edgelock2go_hostname_env != NULL) {
        size_t len = strlen(edgelock2go_hostname_env);
        hostname_local = malloc(len + 1U);
        ASSERT_OR_EXIT(hostname_local!=NULL);
        memcpy(hostname_local, edgelock2go_hostname_env, len + 1U);
        hostname = hostname_local;
    }

#if defined(_WIN32) || defined(_WIN64)
	size_t edgelock2go_port_env_size = 0U;
	ASSERT_OR_EXIT_MSG(_dupenv_s(&edgelock2go_port_env, &edgelock2go_port_env_size, "IOT_AGENT_TEST_EDGELOCK2GO_PORT") == 0, "Error in getting environmental variable");
#else
	edgelock2go_port_env = getenv("IOT_AGENT_TEST_EDGELOCK2GO_PORT");
#endif
	if (edgelock2go_port_env != NULL) {
		int int_port = atoi(edgelock2go_port_env);
		ASSERT_OR_EXIT_MSG(int_port >= 0, "Port is negative value.");
		port = (uint32_t)int_port;
	}

    agent_status = iot_agent_utils_write_edgelock2go_datastore(keystore, datastore, hostname, port,
		iot_agent_trusted_root_ca_certificates, NULL);
    AGENT_SUCCESS_OR_EXIT();

exit:
#if defined(_WIN32) || defined(_WIN64)
	free(edgelock2go_hostname_env);
	free(edgelock2go_port_env);
#endif
    free(hostname_local);
    return agent_status;
}

// This function executes the initialization of the Agent
static iot_agent_status_t initialize_nxp_iot_agent(iot_agent_context_t* pst_iot_agent_context,
	iot_agent_datastore_t* edgelock2go_datastore, iot_agent_datastore_t* datastore, iot_agent_keystore_t* keystore, char* log)
{
#if NXP_IOT_AGENT_HAVE_SSS
	AX_UNUSED_ARG(log);
#endif
#if IOT_AGENT_TIME_MEASUREMENT_ENABLE
    iot_agent_time_context_t iot_agent_init_time = { 0 };
    iot_agent_time_init_measurement(&iot_agent_init_time);
#endif
	iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;

	agent_status = iot_agent_init(pst_iot_agent_context);
	AGENT_SUCCESS_OR_EXIT_MSG("Error in agent initialization\n");

#if NXP_IOT_AGENT_HAVE_SSS
	agent_status = iot_agent_keystore_sss_se05x_init(keystore, EDGELOCK2GO_KEYSTORE_ID, &gex_sss_boot_ctx, true);
	AGENT_SUCCESS_OR_EXIT_MSG("Error in keystore initialization\n");

	agent_status = iot_agent_register_keystore(pst_iot_agent_context, keystore);
	AGENT_SUCCESS_OR_EXIT_MSG("Error in keystore registration\n");
#endif
#if NXP_IOT_AGENT_HAVE_PSA
	agent_status = iot_agent_keystore_psa_init(keystore, EDGELOCK2GO_KEYSTORE_ID);
	AGENT_SUCCESS_OR_EXIT();

	agent_status = iot_agent_register_keystore(pst_iot_agent_context, keystore);
	AGENT_SUCCESS_OR_EXIT();
	write_log(TEST_LOG_ID_REGISTER_ENDPOINT, "{ endpoint: '%s' }", IOT_AGENT_TEST_ENDPOINT_SE05X);
#endif

	agent_status = iot_agent_datastore_init(datastore, 0U, gszDatastoreFilename,
		&iot_agent_service_is_configuration_data_valid);
	AGENT_SUCCESS_OR_EXIT_MSG("Error in datastore initialization\n");

	agent_status = iot_agent_register_datastore(pst_iot_agent_context, datastore);
	AGENT_SUCCESS_OR_EXIT_MSG("Error in datastore registration\n");

	agent_status = iot_agent_datastore_init(edgelock2go_datastore,
		nxp_iot_DatastoreIdentifiers_DATASTORE_EDGELOCK2GO_ID, gszEdgeLock2GoDatastoreFilename,
		&iot_agent_service_is_configuration_data_valid);
	AGENT_SUCCESS_OR_EXIT_MSG("Error in datastore initialization\n");

	agent_status = write_edgelock2go_datastore_from_env(keystore, edgelock2go_datastore);
	AGENT_SUCCESS_OR_EXIT_MSG("Error in datastore writing from env\n");

	agent_status = iot_agent_set_edgelock2go_datastore(pst_iot_agent_context, edgelock2go_datastore);
	AGENT_SUCCESS_OR_EXIT_MSG("Error in datastore setting\n");
#if IOT_AGENT_TIME_MEASUREMENT_ENABLE
    iot_agent_time_conclude_measurement(&iot_agent_init_time);
    iot_agent_time.init_time = iot_agent_time_get_measurement(&iot_agent_init_time);
    iot_agent_time_free_measurement_ctx(&iot_agent_init_time);
#endif

exit:
	return agent_status;
}

// This function executes the Agent
static iot_agent_status_t execute_nxp_iot_agent_service_prov(iot_agent_context_t* pst_iot_agent_context)
{
	iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
	size_t number_of_services = 0U;
	nxp_iot_ServiceDescriptor service_descriptor = nxp_iot_ServiceDescriptor_init_default;

	/* Update Device configuration*/
	nxp_iot_UpdateStatusReport status_report = nxp_iot_UpdateStatusReport_init_default;
	agent_status = iot_agent_update_device_configuration(pst_iot_agent_context, &status_report);

	// In case that the status is IOT_AGENT_UPDATE_FAILED, we do ignore that fact. In this case, we to
	// have a status report. We log the status report. Test cases that expect a provisioning run to
	// complete (successfully or not), shall evaluate the status report to see wheter operations were
	// done as expected from device point of view.
	if (agent_status == IOT_AGENT_UPDATE_FAILED) { agent_status = IOT_AGENT_SUCCESS; }

	if (IOT_AGENT_SUCCESS != agent_status)
	{
		write_log(TEST_LOG_ID_TCP_CONNECT, "%s", "{fail}");
		EXIT_STATUS_MSG(IOT_AGENT_FAILURE, "Error in update device configuration\n");
	}
	write_log(TEST_LOG_ID_TCP_CONNECT, "%s", "{pass}");

	write_status_report_log(&status_report);

	// get total number of services
	number_of_services = iot_agent_get_number_of_services(pst_iot_agent_context);

	for (size_t i = 0U; i < number_of_services; i++)
	{
		agent_status = iot_agent_select_service_by_index(pst_iot_agent_context, i, &service_descriptor);
		AGENT_SUCCESS_OR_EXIT_MSG("Error in service selection\n");

		char* client_certificate_str = pb_bytes_array_to_hex_str(service_descriptor.client_certificate);
#if NXP_IOT_AGENT_HAVE_HOSTCRYPTO_OPENSSL
		//write to files - end
		if (service_descriptor.service_type == nxp_iot_ServiceType_AZURESERVICE) {
			write_log(TEST_LOG_ID_PROVISIONED_SERVICE, "{ service_id: '%" PRIu64 "', hostname: '%s', port: %d, client_cert: '%s' }",
					service_descriptor.identifier, "global.azure-devices-provisioning.net", 8883, client_certificate_str);
		} else {
			write_log(TEST_LOG_ID_PROVISIONED_SERVICE, "{ service_id: '%" PRIu64 "', hostname: '%s', port: %d, client_cert: '%s' }",
					service_descriptor.identifier, service_descriptor.hostname, service_descriptor.port, client_certificate_str);
		}
#endif
#if NXP_IOT_AGENT_HAVE_HOSTCRYPTO_MBEDTLS
		if (service_descriptor.service_type == nxp_iot_ServiceType_AZURESERVICE) {
			write_log(TEST_LOG_ID_PROVISIONED_SERVICE, "{ service_id: '%d', hostname: '%s', port: %d, client_cert: '%s' }",
					(uint32_t)service_descriptor.identifier, "global.azure-devices-provisioning.net", 8883, client_certificate_str);
		} else {
			write_log(TEST_LOG_ID_PROVISIONED_SERVICE, "{ service_id: '%d', hostname: '%s', port: %d, client_cert: '%s' }",
					(uint32_t)service_descriptor.identifier, service_descriptor.hostname, service_descriptor.port, client_certificate_str);
		}
#endif
#ifdef _WIN32
#if NXP_IOT_AGENT_HAVE_SSS
		// this is just used to test the function for coverage purpose
		char keyref_filename[] = "temp_file";
		if (IOT_AGENT_SUCCESS != iot_agent_utils_write_key_ref_service_pem(pst_iot_agent_context, keyref_filename))
		{
			IOT_AGENT_INFO("Error in file creatuon[%s]", keyref_filename);
		}
		else
		{
			IOT_AGENT_INFO("Created service keyref file [%s]", keyref_filename);
		}
#endif
#endif
		free(client_certificate_str);
	}
exit:
	iot_agent_free_update_status_report(&status_report);
	iot_agent_free_service_descriptor(&service_descriptor);
    return agent_status;
}

// Dispatcher function which decodes and parses the incoming packet and
// builds the response to be transmitted
static iot_agent_status_t dispatch_rpc_request(int argc, const char *argv[], iot_agent_context_t* pAgentContext,
    iot_agent_datastore_t* pst_edgelock2go_datastore, iot_agent_datastore_t* pst_datastore, iot_agent_keystore_t* pst_keystore, nxp_iot_RpcRequest* pRpcRequest, nxp_iot_RpcResponse* pRpcResponse, size_t* cmd)
{
	iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
	size_t offset = 0U;
	size_t size = 0U;
#if NXP_IOT_AGENT_HAVE_HOSTCRYPTO_OPENSSL
	char* object_id;
#endif
#if NXP_IOT_AGENT_HAVE_SSS
	iot_agent_keystore_sss_se05x_context_t* se05x_context = NULL;
	sss_se05x_session_t* se05x_session = NULL;
#endif
#if IOT_AGENT_TIME_MEASUREMENT_ENABLE
	iot_agent_time_context_t iot_agent_total_time = { 0 };
#endif
#if ((NXP_IOT_AGENT_HAVE_HOSTCRYPTO_OPENSSL) || (AX_EMBEDDED && defined(USE_RTOS) && USE_RTOS == 1))
	char* serviceDescriptorId = NULL;
#endif
	ASSERT_OR_EXIT_MSG(pRpcRequest->id == RPC_ID, "Wrong ID\n");
	ASSERT_OR_EXIT_MSG(pRpcRequest->arg_count >= 1U, "At least one argument needs to be present in the packet\n");

	int command_index;
	agent_status = search_argument_per_position(pRpcRequest, RPC_ARGUMENT_POS_CMD, &command_index);
	AGENT_SUCCESS_OR_EXIT_MSG("Command argument is missing in the packet\n");

	*cmd = pRpcRequest->arg[command_index].payload.data.uint32_arg;

	switch (*cmd)
	{
    case RPC_REQUEST_CMD_INTIALIZE_AGENT:
        agent_status = initialize_nxp_iot_agent(pAgentContext, pst_edgelock2go_datastore, pst_datastore, pst_keystore, log_ptr);
        AGENT_SUCCESS_OR_EXIT_MSG("Error in the agent initialization; Critical error: restart the Remote Runner\n\n");
        FPRINTF("Start Command received successfully\n");
        build_rpc_response_status(pRpcResponse, RPC_RESPONSE_STATE_SUCCESS);
        break;
    case RPC_REQUEST_CMD_START_PROVISIONING_CLIENT:
#if NXP_IOT_AGENT_HAVE_SSS
        iot_agent_session_disconnect(&gex_sss_boot_ctx);
        agent_status = remote_provisioning_start("127.0.0.1", "7050");
        AGENT_SUCCESS_OR_EXIT_MSG("Offline Provisioning Fail, Check logs");
        agent_status = iot_agent_session_connect(&gex_sss_boot_ctx);
        AGENT_SUCCESS_OR_EXIT_MSG("Reconnect failed, Check logs");
#endif //NXP_IOT_AGENT_HAVE_SSS
        build_rpc_response_status(pRpcResponse, RPC_RESPONSE_STATE_SUCCESS);
        break;
    case RPC_REQUEST_CMD_START:
        start_log_ptr = local_buffer;
        log_ptr = start_log_ptr;

#if IOT_AGENT_TIME_MEASUREMENT_ENABLE
        iot_agent_time_init_measurement(&iot_agent_total_time);
#endif
        agent_status = execute_nxp_iot_agent_service_prov(pAgentContext);
#if IOT_AGENT_TIME_MEASUREMENT_ENABLE
        iot_agent_time_conclude_measurement(&iot_agent_total_time);
        iot_agent_time.total_time = iot_agent_time_get_measurement(&iot_agent_total_time) + iot_agent_time.init_time;
        iot_agent_time_free_measurement_ctx(&iot_agent_total_time);
#endif
        if (agent_status != IOT_AGENT_SUCCESS)
        {
            IOT_AGENT_ERROR("Error in agent execution\n");
#if NXP_IOT_AGENT_HAVE_SSS
            agent_status = iot_agent_session_init(argc, argv, &gex_sss_boot_ctx);
            AGENT_SUCCESS_OR_EXIT_MSG("Critical error: restart the Remote Runner\n");
#endif //NXP_IOT_AGENT_HAVE_SSS
        }

#if IOT_AGENT_TIME_MEASUREMENT_ENABLE
        write_log(TEST_LOG_ID_PERFORMANCE, "{ entireTime: %ld, initTime: %ld, prepareTlsTime: %ld, networkConnectTime: %ld, processProvisionTime: %ld}",
            iot_agent_time.total_time, iot_agent_time.init_time, iot_agent_time.prepare_tls_time, iot_agent_time.network_connect_time, iot_agent_time.process_provision_time);
#endif
		FPRINTF("Start Command received successfully\n");
		build_rpc_response_status(pRpcResponse, RPC_RESPONSE_STATE_SUCCESS);
		break;
	case RPC_REQUEST_CMD_STOP:
		FPRINTF("Stop Command received successfully\n");
		build_rpc_response_status(pRpcResponse, RPC_RESPONSE_STATE_SUCCESS);
		break;
	case RPC_REQUEST_CMD_WAIT:
		FPRINTF("Wait Command received successfully\n");
		build_rpc_response_status(pRpcResponse, RPC_RESPONSE_STATE_SUCCESS);
		break;
	case RPC_REQUEST_CMD_GET_LOG_LENGTH:
		FPRINTF("Get Log Length Command received successfully\n");
		build_rpc_response_get_string_length(pRpcResponse, RPC_RESPONSE_STATE_SUCCESS, (size_t)(log_ptr - start_log_ptr));
		break;
	case RPC_REQUEST_CMD_GET_LOG:
		agent_status = parse_get_string_command(pRpcRequest, &offset, &size);
		AGENT_SUCCESS_OR_EXIT_MSG("Error in parsing command\n");
		FPRINTF("Get Log Command received successfully\n");
		build_rpc_response_get_string(pRpcResponse, RPC_RESPONSE_STATE_SUCCESS, offset, size, start_log_ptr);
		break;
	case RPC_REQUEST_CMD_SEND_CMD_LENGTH:
		FPRINTF("Send APDU Length Command received successfully\n");
		agent_status = parse_send_cmd_length_command(pRpcRequest);
		AGENT_SUCCESS_OR_EXIT_MSG("Error in parsing the Send APDU length command\n");
		build_rpc_response_status(pRpcResponse, RPC_RESPONSE_STATE_SUCCESS);
		break;
	case RPC_REQUEST_CMD_SEND_CMD:
		FPRINTF("APDU Command received successfully\n");
		// Attention, this is operating on gex_sss_boot_ctx.session directly (bypassing the agent and the agent's keystore).
		agent_status = parse_send_cmd_command(pRpcRequest);
		AGENT_SUCCESS_OR_EXIT_MSG("Error in parsing the Send APDU command\n");
		build_rpc_response_status(pRpcResponse, RPC_RESPONSE_STATE_SUCCESS);
		break;
	case RPC_REQUEST_CMD_STOP_AND_CLOSE:
		FPRINTF("Stop&Close Command received successfully\n");
		build_rpc_response_status(pRpcResponse, RPC_RESPONSE_STATE_SUCCESS);
		break;
	case RPC_REQUEST_CMD_IS_RUNNING:
		FPRINTF("Is running Command received successfully\n");
		build_rpc_response_status(pRpcResponse, RPC_RESPONSE_STATE_SUCCESS);
		break;
#if NXP_IOT_AGENT_HAVE_HOSTCRYPTO_OPENSSL
	case RPC_REQUEST_CMD_WRITE_PEM:
		FPRINTF("Write PEM Command received successfully\n");
		object_id = malloc((size_t)(OBJECT_ID_SIZE + 1U));
		ASSERT_OR_EXIT_STATUS_MSG(object_id != NULL, IOT_AGENT_ERROR_MEMORY, "Error in object ID allocation\n");
		agent_status = parse_get_string(pRpcRequest, object_id);
		if (agent_status != IOT_AGENT_SUCCESS)
		{
			free(object_id);
			EXIT_STATUS_MSG(IOT_AGENT_FAILURE, "Not supported command\n");
		}

		// Attention, this is bypassing the agent and the keystore of the agent and operating directly on an
		// the boot_ctx! This can interfere with regular agent operation, take care.
		agent_status = execute_write_pem_test(&gex_sss_boot_ctx.ks, object_id);

		// return with success if this point is reached to communicate to Agent the
		// result of the test
		if (agent_status != IOT_AGENT_SUCCESS)
		{
			build_rpc_response_status(pRpcResponse, RPC_RESPONSE_STATE_ERROR);
		}
		else
		{
			build_rpc_response_status(pRpcResponse, RPC_RESPONSE_STATE_SUCCESS);
		}
		free(object_id);
		EXIT_STATUS_MSG(IOT_AGENT_SUCCESS, "Not supported command\n");
		break;
#endif
	case RPC_REQUEST_CMD_FACTORY_RESET:
		FPRINTF("Factory Reset Command received successfully\n");
#if NXP_IOT_AGENT_HAVE_SSS
		// TODO: this is always using the first keystore, so be careful when triggering this.
		// Eventually, it needs an additional parameter for the keystore index or id.
		// This is SE05x specific, so the keystore must have the right type!
		if (pAgentContext->numKeystores < 1U) {
			EXIT_STATUS_MSG(IOT_AGENT_FAILURE, "No keystore registered\n");
		}
		if (pAgentContext->keystores[0]->type != IOT_AGENT_KS_SSS_SE05X) {
			EXIT_STATUS_MSG(IOT_AGENT_FAILURE, "Wrong keystore type\n");
		}
		se05x_context = (iot_agent_keystore_sss_se05x_context_t*)pAgentContext->keystores[0]->context;
		execute_factory_reset(se05x_context->boot_context);
#endif //NXP_IOT_AGENT_HAVE_SSS
		build_rpc_response_status(pRpcResponse, RPC_RESPONSE_STATE_SUCCESS);
		break;
	case RPC_REQUEST_CMD_GET_RESP_LENGTH:
		FPRINTF("Get Resp Length Command received successfully\n");
		build_rpc_response_get_string_length(pRpcResponse, RPC_RESPONSE_STATE_SUCCESS, (size_t)(resp_apdu_length));
		break;
	case RPC_REQUEST_CMD_GET_RESP:
		agent_status = parse_get_string_command(pRpcRequest, &offset, &size);
		AGENT_SUCCESS_OR_EXIT_MSG("Error in parsing command\n");
		FPRINTF("Get Resp Command received successfully\n");
		build_rpc_response_get_string(pRpcResponse, RPC_RESPONSE_STATE_SUCCESS, offset, size, resp_apdu_ptr);
		break;
	case RPC_REQUEST_CMD_SET_ECC_CURVE:
#if NXP_IOT_AGENT_HAVE_SSS
		// TODO: this is always using the first keystore, so be careful when triggering this.
		// Eventually, it needs an additional parameter for the keystore index or id.
		// This is SE05x specific, so the keystore must have the right type!
		if (pAgentContext->numKeystores < 1U) {
			EXIT_STATUS_MSG(IOT_AGENT_FAILURE, "No keystore registered\n");
		}
		if (pAgentContext->keystores[0]->type != IOT_AGENT_KS_SSS_SE05X) {
			EXIT_STATUS_MSG(IOT_AGENT_FAILURE, "Wrong keystore type\n");
		}
		sss_key_store_t* sss_key_store = NULL;
		agent_status = iot_agent_keystore_sss_se05x_get_sss_key_store(pAgentContext->keystores[0]->context, &sss_key_store);
		AGENT_SUCCESS_OR_EXIT_MSG("iot_agent_keystore_sss_se05x_get_sss_key_store failed: 0x%08x\n", agent_status);

		se05x_session = (sss_se05x_session_t*)sss_key_store->session;
		agent_status = parse_set_ecc_curve_command(pRpcRequest, se05x_session);
		AGENT_SUCCESS_OR_EXIT_MSG("Error in parsing command\n");
		FPRINTF("Set Ecc curver received successfully\n");
#endif //NXP_IOT_AGENT_HAVE_SSS
		build_rpc_response_status(pRpcResponse, RPC_RESPONSE_STATE_SUCCESS);
		break;
	case RPC_REQUEST_CMD_CONNECT_SERVICES:
#if NXP_IOT_AGENT_HAVE_SSS
		if (execute_connect_to_services(pAgentContext) != IOT_AGENT_SUCCESS) {
			IOT_AGENT_ERROR("Error in connection to services\n");
		} else {
			IOT_AGENT_INFO("Connection to services was successfull\n");
		}
		FPRINTF("RPC_REQUEST_CMD_CONNECT_SERVICES received successfully\n");
#endif //NXP_IOT_AGENT_HAVE_SSS
		build_rpc_response_status(pRpcResponse, RPC_RESPONSE_STATE_SUCCESS);
		break;
	case RPC_REQUEST_CMD_ENDPOINT_REQUEST:
		handle_endpoint_request(pRpcRequest, pRpcResponse, pAgentContext);
		AGENT_SUCCESS_OR_EXIT_MSG("Error in handle_endpoint_request command\n");
		// Note, the response is assembled in the handler already, no build_rpc_response_status required here!
		break;
#if ((NXP_IOT_AGENT_HAVE_HOSTCRYPTO_OPENSSL) || (AX_EMBEDDED && defined(USE_RTOS) && USE_RTOS == 1))
	case RPC_REQUEST_CMD_COS_OVER_RTP:
		serviceDescriptorId = malloc((size_t)(OBJECT_ID_SIZE + 1U));
		memset(serviceDescriptorId, 0, (size_t)(OBJECT_ID_SIZE + 1U));
		agent_status = parse_get_string(pRpcRequest, serviceDescriptorId);
		if (execute_cos_over_rtp_connection(pAgentContext, serviceDescriptorId) != IOT_AGENT_SUCCESS) {
			IOT_AGENT_ERROR("Error in connection to services\n");
		}
		else {
			IOT_AGENT_INFO("Connection to services was successfull\n");
		}
		free(serviceDescriptorId);
		FPRINTF("RPC_REQUEST_CMD_COS_OVER_RTP received successfully\n");
		build_rpc_response_status(pRpcResponse, RPC_RESPONSE_STATE_SUCCESS);
		break;
#endif
#if NXP_IOT_AGENT_HAVE_PSA
	case RPC_REQUEST_CMD_EXECUTE_PSA_API:
		IOT_AGENT_INFO("Execution of PSA API");
		agent_status = parse_execute_psa_api(pRpcRequest, pRpcResponse);
		break;
	case RPC_REQUEST_CMD_PSA_INJECT_CLAIM_CODE:
		IOT_AGENT_INFO("Execution of claim code incjection");
		agent_status = parse_inject_claim_code(pRpcRequest, pRpcResponse);
		break;
#endif
	default:
		EXIT_STATUS_MSG(IOT_AGENT_FAILURE, "Not supported command\n");
	}
exit:
	return agent_status;
}

// Callback function which will be called during packet transmission to client
static bool remote_write_callback(pb_ostream_t *stream, const pb_byte_t *buf, size_t count)
{
	void* network_context = stream->state;

#ifdef _WIN32
	size_t written = (size_t)send((SOCKET)network_context, (const char *)buf, count, 0);
#else
	size_t written = (size_t)send((uintptr_t)network_context, (char *)buf, count, 0);
#endif

	return (written == count);
}

// Callback function which will be called when one packet is received by the Server
static bool remote_read_callback(pb_istream_t *stream, uint8_t *buf, size_t count)
{
	void* network_context = stream->state;
	while (count > 0U)
	{
#ifdef _WIN32
		size_t read = (size_t)recv((SOCKET)network_context, (char *)buf, count, 0);
#else
		size_t read = (size_t)recv((uintptr_t)network_context, (char *)buf, count, 0);
#endif

		if (read <= 0U)
		{
			stream->bytes_left = 0U; /* EOF */
			break;
		}

		buf += read;
		count -= read;

	}

	return (count == 0U);
}

// This function is waiting for a message from the client
// When is received is dispatching it and executing the proper function
static iot_agent_status_t iot_agent_test_remote_synchronization_point(int argc, const char *argv[], iot_agent_context_t *iot_agent_context,
    iot_agent_datastore_t* pst_edgelock2go_datastore, iot_agent_datastore_t* pst_datastore, iot_agent_keystore_t* pst_keystore, int socket_accept_conn_fd, size_t* cmd)
{
	iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
	pb_istream_t istream = { &remote_read_callback, (void *)(intptr_t)socket_accept_conn_fd, SIZE_MAX };
	pb_ostream_t ostream = { &remote_write_callback, (void *)(intptr_t)socket_accept_conn_fd, SIZE_MAX, 0U };

	nxp_iot_RpcRequest rpcRequest = nxp_iot_RpcRequest_init_default;
	nxp_iot_RpcResponse rpcResponse = nxp_iot_RpcResponse_init_default;

	// pb_decode_delimited is a blocking function which will exit when a packet is
	// successfully received
	if (!pb_decode_delimited(&istream, nxp_iot_RpcRequest_fields, &rpcRequest))
	{
		EXIT_STATUS_MSG(IOT_AGENT_FAILURE, "Decode Server Message failed: %s \n", PB_GET_ERROR(&istream));
	}

	FPRINTF("Packet successfully decoded\n");

	agent_status = dispatch_rpc_request(argc, argv, iot_agent_context, pst_edgelock2go_datastore, pst_datastore, pst_keystore, &rpcRequest, &rpcResponse, cmd);
	AGENT_SUCCESS_OR_EXIT_MSG("Error in dispatching the request\n");

	// pb_encode_delimited is a blocking function which will exit when a packet is
	// successfully received
	if (!(pb_encode_delimited(&ostream, nxp_iot_RpcResponse_fields, &rpcResponse)))
	{
		EXIT_STATUS_MSG(IOT_AGENT_FAILURE, "Encode Server Message failed: %s \n", PB_GET_ERROR(&ostream));
	}

	FPRINTF("Packet successfully encoded\n");
exit:
	return agent_status;
}

static iot_agent_status_t disconnect_socket(int socket_fd)
{
	iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;

	if (closesocket(socket_fd))
	{
		EXIT_STATUS_MSG(IOT_AGENT_FAILURE, "Error in opening socket\n");
	}
exit:
#ifdef _WIN32
	if (WSACleanup() != 0) {
		agent_status = IOT_AGENT_FAILURE;
	}
#endif
	return agent_status;
}


// This function initialize the server connection
static iot_agent_status_t initialize_server_connection(const char* server_port, int* pi_socket_fd)
{
	iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
#if !(defined(AX_EMBEDDED) && defined(USE_RTOS) && USE_RTOS == 1)
#ifdef _WIN32
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		IOT_AGENT_ERROR("Error in WSA startup\n");
		return IOT_AGENT_FAILURE;
	}
#endif

    // Fill in the address structure containing self address
    //struct sockaddr_in myaddr;
    struct addrinfo hints;
	struct addrinfo *servinfo = NULL;
    int rv;
    int res;
    struct linger linger_opt = { 1, 0 }; // Linger active, timeout 0

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET; // only listen on ipv4 addresses
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE; // use my IP

	rv = getaddrinfo(NULL, server_port, &hints, &servinfo);
	ASSERT_OR_EXIT_MSG(rv == 0, "getaddrinfo: %s\n", gai_strerror(rv));

	*pi_socket_fd = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol);
    ASSERT_OR_EXIT_MSG(*pi_socket_fd >= 0, "Error in opening socket\n");
    // Bind a socket to the address
    res = bind(*pi_socket_fd, servinfo->ai_addr, servinfo->ai_addrlen);
    ASSERT_OR_EXIT_MSG(res >= 0, "Error in server address binding\n");

    // Set the "LINGER" timeout to zero, to close the listen socket
    // immediately at program termination.
    res = setsockopt(*pi_socket_fd, SOL_SOCKET, SO_LINGER, (const char*)&linger_opt, sizeof(linger_opt));
    ASSERT_OR_EXIT_MSG(res >= 0, "Error in setting socket options\n");

    // Now, listen for a connection
    res = listen(*pi_socket_fd, 1);
    ASSERT_OR_EXIT_MSG(res >= 0, "Error in connection listening\n");
    AGENT_SUCCESS_OR_EXIT_MSG("Error in opening socket\n");
exit:
    // the socket is closed externally in case of error in the function
    if (servinfo != NULL)
    {
        freeaddrinfo(servinfo);
    }
#elif defined(LPC_ENET)
    int res;
    struct sockaddr_in name;
    socklen_t namelen = sizeof(name);
    char buffer[80];
    *pi_socket_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
	ASSERT_OR_EXIT_MSG(*pi_socket_fd >= 0, "Error in opening socket\n");
    getsockname(*pi_socket_fd, (struct sockaddr *)&name, &namelen);

    // Bind a socket to the address
    inet_ntop(AF_INET, &name.sin_addr, buffer, 80);
    name.sin_port = htons(atoi(server_port));
    res = bind(*pi_socket_fd, (struct sockaddr*)&name, sizeof(name));
    ASSERT_OR_EXIT_MSG(res >= 0, "Error in server address binding\n");

    // Now, listen for a connection
    res = listen(*pi_socket_fd, 1);
    ASSERT_OR_EXIT_MSG(res >= 0, "Error in connection listening\n");
exit:
#elif defined(LPC_WIFI)
	int ret = 0;
	mwm_sockaddr_t http_srv_addr = {0};
    char ssid[33]    = {0};
    char ip_addr[16] = {0};

	http_srv_addr.port = atoi(server_port);

    ret = mwm_wlan_status();

    ASSERT_OR_EXIT_MSG(ret == MWM_CONNECTED, "WiFi not connected\n");

    ret = mwm_wlan_info(ssid, ip_addr);
	strcpy(http_srv_addr.host, ip_addr);
    printf("Starting server on Port %d\n", http_srv_addr.port);

    *pi_socket_fd = mwm_socket(MWM_TCP);

    ASSERT_OR_EXIT_MSG(*pi_socket_fd >= 0, "Error in opening socket\n");

    ret = mwm_bind(*pi_socket_fd, &http_srv_addr, sizeof(http_srv_addr));

    ASSERT_OR_EXIT_MSG(ret >= 0, "ERROR: Socket bind error\n");

    printf("Bind complete Port %d\n", http_srv_addr.port);

    ret = mwm_listen(*pi_socket_fd, 1);

    ASSERT_OR_EXIT_MSG(ret >= 0, "Error in connection listening\n");
exit:
#endif
	return agent_status;
}

// This function waits for a client connection
static iot_agent_status_t wait_on_client_connection(int socket_fd, int* pi_socket_accept_fd)
{
	iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;

#if !defined(LPC_WIFI)
	// Accept a connection (the "accept" command waits for a connection with
	// no timeout limit...)
	struct sockaddr_storage peeraddr;
	socklen_t peeraddr_len = sizeof(peeraddr);

	*pi_socket_accept_fd = accept(socket_fd, (struct sockaddr*) &peeraddr, &peeraddr_len);
#else
    *pi_socket_accept_fd = mwm_accept(socket_fd);
#endif
    ASSERT_OR_EXIT_MSG(*pi_socket_accept_fd >= 0, "Failed while waiting on agent connection");

exit:
	return agent_status;
}

#if AX_EMBEDDED && defined(USE_RTOS) && USE_RTOS == 1

typedef struct cli_arguments
{
    int    c;
    const char **v;
} cli_arguments_t;

void remote_runner_start_task(void *args)
{
    iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;

    network_init();

    const TickType_t xDelay = 2 * 1000 / portTICK_PERIOD_MS;

    for (;;)
    {
		iot_agent_freertos_led_start();

        cli_arguments_t* a = args;
        agent_status = remote_runner_start(a->c, a->v);

		if (agent_status == IOT_AGENT_SUCCESS)
		{
			iot_agent_freertos_led_success();
		}
		else
		{
			iot_agent_freertos_led_failure();
		}

        vTaskDelay(xDelay);
    }
}

#endif

int main(int argc, const char *argv[])
{
#if AX_EMBEDDED && defined(USE_RTOS) && USE_RTOS == 1

	iot_agent_freertos_bm();

	cli_arguments_t args;
    args.c = argc;
    args.v = argv;

    if (xTaskCreate(&remote_runner_start_task,
        "remote_runner_start_session_task",
        EX_SSS_BOOT_RTOS_STACK_SIZE,
        (void *)&args,
        (tskIDLE_PRIORITY),
        NULL) != pdPASS) {
        IOT_AGENT_INFO("Task creation failed!.\r\n");
        while (1)
            ;
    }

    /* Run RTOS */
    vTaskStartScheduler();

    return 1;
#else
	return remote_runner_start(argc, argv);
#endif
}

// The Remote Runner Server is able to receive commands from a Remote Runner client and
// control the NXP Iot Agent Demo application
iot_agent_status_t remote_runner_start(int argc, const char *argv[])
{
    iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;

#if NXP_IOT_AGENT_HAVE_SSS
    agent_status = iot_agent_session_init(argc, argv, &gex_sss_boot_ctx);
	if (agent_status != IOT_AGENT_SUCCESS)
	{
		IOT_AGENT_ERROR("Critical error: restart the Remote Runner\n");
		return agent_status;
	}
#endif //NXP_IOT_AGENT_HAVE_SSS
    // socket file descriptor
	int socket_fd = 0;
	int socket_accept_conn_fd = 0;

	iot_agent_context_t iot_agent_context = { 0 };

	// The datastore holding data to connect to EdgeLock 2GO cloud service.
	iot_agent_datastore_t edgelock2go_datastore = { 0 };

	// The datastore that is to be filled with service descriptors
	// for customer cloud services.
	iot_agent_datastore_t datastore = { 0 };

	// The keystore (it holds credentials for connecting to EdgeLock 2GO
	// cloud service as well as for customer cloud services).
	iot_agent_keystore_t keystore = { 0 };

	size_t cmd;

#if NXP_IOT_AGENT_HAVE_PSA
	psa_status_t psa_status = PSA_SUCCESS;
	psa_status = psa_crypto_init();
	PSA_SUCCESS_OR_EXIT_MSG("Error in the initialization of the command\n");
#endif

	if (argc > 1) {
		gserver_port = argv[1];
	}

	// initialize the log pointers to the start of the buffer
	start_log_ptr = local_buffer;
	log_ptr = start_log_ptr;

	printf("******************************************************************************\n");
	printf("Establishing the server on port %s...\n\n", gserver_port);
	fflush(stdout);

	agent_status = initialize_server_connection(gserver_port, &socket_fd);
	AGENT_SUCCESS_OR_EXIT_MSG("Error in server initialization\n");

	while (1)
	{
		printf("******************************************************************************\n");
		printf("Waiting client connection on port %s...\n", gserver_port);

		// in case of previously open socket, close it before to go to next opening of socket
		if (socket_accept_conn_fd > 0)
		{
#if !defined(LPC_WIFI)
			// in case of error, stay in the applization, but write the error
			if (shutdown(socket_accept_conn_fd, 2))
			{
				IOT_AGENT_ERROR("Error in shutting down the socket\n");
			}
#endif

			if (closesocket(socket_accept_conn_fd))
			{
				IOT_AGENT_ERROR("Error in closing the socket\n");
			}
		}

		// wait until a connection from a client is successful
		do
		{
			agent_status = wait_on_client_connection(socket_fd, &socket_accept_conn_fd);

			// in case of error, stay in the applization, but write the error
			if (agent_status != IOT_AGENT_SUCCESS)
			{
				IOT_AGENT_ERROR("Error in client socket connection\n");
			}
		} while (agent_status != IOT_AGENT_SUCCESS);

		// connection established
		// the synchronization touchpoint: it waits for a message from the
		// client and executes the proper function

        // reset the logging
		start_log_ptr = local_buffer;
		log_ptr = start_log_ptr;
        cmd = 0U;

		// this is the receive-dispatch-transmit loop
		while (1)
		{
			if ((cmd == RPC_REQUEST_CMD_STOP) || (cmd == RPC_REQUEST_CMD_STOP_AND_CLOSE))
			{
				// exit the loop in case of STOP or STOP_AND_CLOSE commands
				break;
			}

			// the synchronization touchpoint: it waits for a message from the
			// client and executes the proper function
            agent_status = iot_agent_test_remote_synchronization_point(argc, argv, &iot_agent_context, &edgelock2go_datastore, &datastore, &keystore, socket_accept_conn_fd, &cmd);
			if (agent_status != IOT_AGENT_SUCCESS)
			{
				// in case of communication error, exit the loop and return in listening mode
				IOT_AGENT_ERROR("Error in synchronization with client\n");
				break;
			}
		}

        IOT_AGENT_INFO("Freeing keystore and datastore\n");
        iot_agent_datastore_free(&edgelock2go_datastore);
		iot_agent_datastore_free(&datastore);
		iot_agent_keystore_free(&keystore);

		if (cmd == RPC_REQUEST_CMD_STOP_AND_CLOSE)
		{
			agent_status = IOT_AGENT_SUCCESS;
			goto exit;
		}
	}

exit:
	agent_status = disconnect_socket(socket_fd);
	if (agent_status != IOT_AGENT_SUCCESS)
	{
		IOT_AGENT_ERROR("Error in socket closing");
		agent_status = IOT_AGENT_FAILURE;
	}
	iot_agent_datastore_free(&edgelock2go_datastore);
	iot_agent_datastore_free(&datastore);
	iot_agent_keystore_free(&keystore);

    exit(agent_status);
}
