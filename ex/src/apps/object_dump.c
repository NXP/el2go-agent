/* Copyright 2019-2021 NXP
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

 // Define this function here as it has influence on the
 // logging in the agent itself if included
#define IOT_AGENT_TEST      1

#include <nxp_iot_agent_session.h>
#include <nxp_iot_agent_macros.h>
#include <nxp_iot_agent_keystore_sss_se05x.h>


static ex_sss_boot_ctx_t gex_sss_boot_ctx;

#define DEBUG 0
#ifdef _MSC_VER
#define ACCESS _access
#else
#define ACCESS access
#endif

static void print_usage()
{

	printf("Generate object reference file for a given ObjId\n");
	printf(" Usage:\n");
	printf("  ObjId should be in the hex prefixed by 0x:\n");
    printf(" To use default port 127.0.0.1:8050: keyref_dump 0xDEAD1234\n");
    printf(" To override Default port:           keyref_dump 0xDEAD1234 1.2.3.4:8888\n");
	printf("\n");
}

int main(int argc, const char *argv[])
{
    iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
    sss_status_t sss_status;
    uint32_t objid = 0U;
    char filename[24] = "ObjRef_0x";
    sss_object_t obj = { 0 };
    int remove_check = 0;
    iot_agent_keystore_t keystore = { 0 };

    if (argc < 2 || argc > 3 || ((argv[1][0] != '0') || (argv[1][1] != 'x' && argv[1][1] != 'X')))
    {
        printf(" Wrong Usage:\n");
        print_usage();
        return -1;
    }

    if (argc == 2)
    {
        agent_status = iot_agent_session_init(0, NULL, &gex_sss_boot_ctx);
    }
    else
    {
        agent_status = iot_agent_session_init(argc, argv, &gex_sss_boot_ctx);
    }
    AGENT_SUCCESS_OR_EXIT();

#if defined(_WIN32) && (_WIN32 == 1)
	objid = (uint32_t)_strtoi64(argv[1], NULL, 0);
#else
	objid = (uint32_t)strtoull(argv[1], NULL, 0);
#endif

	snprintf(filename + 9, sizeof(filename) - 9, "%X", objid);

	strcat(filename, ".pem");
	if (ACCESS(filename, F_OK) == 0)
	{
        remove_check = remove(filename);
        ASSERT_OR_EXIT(remove_check == 0);
	}

    sss_status = sss_key_object_init(&obj, &gex_sss_boot_ctx.ks);
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
	case kSSS_CipherType_EC_BARRETO_NAEHRIG: /* Barreto Naehrig curve */
        agent_status = iot_agent_utils_write_key_ref_pem(&gex_sss_boot_ctx.ks, &obj, objid, filename);
        AGENT_SUCCESS_OR_EXIT_MSG("Failed to create keyref file")
        printf("Generated Key reference file for ObjectId 0x%x in %s \n", objid, filename);
		break;
	case kSSS_CipherType_Certificate: /* Certificate */
	case kSSS_CipherType_Binary: /* Binary */
        agent_status = iot_agent_keystore_sss_se05x_init(&keystore, 0, &gex_sss_boot_ctx, true);
        AGENT_SUCCESS_OR_EXIT_MSG("iot_agent_keystore_sss_se05x_init failed: 0x%08x", agent_status);
        agent_status = iot_agent_utils_write_certificate_pem_from_keystore(&keystore, objid, filename);
        AGENT_SUCCESS_OR_EXIT_MSG("Failed to write certificate file");
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
