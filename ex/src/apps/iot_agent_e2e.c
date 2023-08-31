/*
 * Copyright 2019-2021 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>

#ifdef _WIN32
#include <direct.h>
#include <dirent_win32.h>
#else
#include <dirent.h>
#endif

// Define this function here as it has influence on the
// logging in the agent itself if included
#define IOT_AGENT_TEST      1

#include <nxp_iot_agent.h>
#include <nxp_iot_agent_keystore_sss_se05x.h>
#include <nxp_iot_agent_datastore_fs.h>
#include <nxp_iot_agent_datastore_plain.h>
#include <nxp_iot_agent_utils.h>
#include <nxp_iot_agent_session.h>
#include <nxp_iot_agent_macros.h>

static ex_sss_boot_ctx_t gex_sss_boot_ctx;

const char * gszDatastoreFilename = "datastore.bin";

#define TEST_LOG_ID_REGISTER_ENDPOINT   "register_endpoint"
#define TEST_LOG_ID_EDGELOCK2GO_CONNECT      "edgelock2go_connect"
#define TEST_LOG_ID_PROVISIONED_SERVICE "provisioned_service"
#define TEST_LOG_ID_TERMINATED          "terminated"

#define IOT_AGENT_TEST_ENDPOINT_SE05X           "SE05X"
#define IOT_AGENT_TEST_ENDPOINT_DATASTORE_FS    "DATASTORE"
#define IOT_AGENT_TEST_ENDPOINT_DATASTORE_PLAIN "DATASTORE_PLAIN"

const char* terminate_message = "terminate";
bool terminated = false;


// When running tests capturing the STDOUT, we use a pipe on STDIN to synchronize
// with test framework. As soon as we can read a line from the pipe we can
// continue - until the next time we hit a synchronization point.
static void iot_agent_test_synchronization_point()
{
    const char* synch_str = getenv("IOT_AGENT_TEST_SYNCHRONIZATION_MESSAGE");
    if (synch_str == NULL) { return; }
    char msg[80];
    IOT_AGENT_TEST_LOG(synch_str, "");
    fflush(stdout);
    fgets(msg, (int)(sizeof(msg) - 1U), stdin);
    msg[strcspn(msg, "\n")] = 0;

    if (strcmp(terminate_message, msg) == 0)
        terminated = true;
}


int main(int argc, const char *argv[])
{
	iot_agent_status_t agent_status = IOT_AGENT_SUCCESS;
    sss_status_t sss_status;
	iot_agent_context_t iot_agent_context = { 0 };

	// The datastore holding data to connect to EdgeLock 2GO cloud service.
	iot_agent_datastore_t edgelock2go_datastore = { 0 };

	// The datastore that is to be filled with service descriptors
	// for customer cloud services.
	iot_agent_datastore_t datastore_fs = { 0 };
	iot_agent_datastore_t datastore_plain = { 0 };

	// The keystore (it holds credentials for connecting to EdgeLock 2GO
	// cloud service as well as for customer cloud services).
	iot_agent_keystore_t keystore = { 0 };

	nxp_iot_ServiceDescriptor service_descriptor = nxp_iot_ServiceDescriptor_init_default;

    agent_status = iot_agent_session_init(argc, argv, &gex_sss_boot_ctx);
    AGENT_SUCCESS_OR_EXIT();

	agent_status = iot_agent_init(&iot_agent_context);
	AGENT_SUCCESS_OR_EXIT();

	// Read endpoint configuration from environment variables.
	//bool endpoint_found = true;
	for (size_t i = 0U; i < NXP_IOT_AGENT_MAX_NUM_ENDPOINTS; i++)
	{
		char buf[100];
		snprintf(buf, sizeof(buf), "IOT_AGENT_TEST_ENDPOINT_%zu", i);
		const char* next_endpoint = getenv(buf);
		if (next_endpoint != NULL) {
			if (strcmp(next_endpoint, IOT_AGENT_TEST_ENDPOINT_SE05X) == 0) {
				// TODO: the middleware does not allow compilation for more than one applet right now, so runtime
				// configuration is not really an option.
#if SSS_HAVE_APPLET_SE05X_IOT
				agent_status = iot_agent_keystore_sss_se05x_init(&keystore, EDGELOCK2GO_KEYSTORE_ID, &gex_sss_boot_ctx, true);
				AGENT_SUCCESS_OR_EXIT();

				agent_status = iot_agent_register_keystore(&iot_agent_context, &keystore);

				AGENT_SUCCESS_OR_EXIT();
				IOT_AGENT_TEST_LOG(TEST_LOG_ID_REGISTER_ENDPOINT, "{ endpoint: '%s' }", IOT_AGENT_TEST_ENDPOINT_SE05X);
#else
				EXIT_STATUS_MSG(IOT_AGENT_FAILURE, "support for [%s] not compiled-in", next_endpoint);
#endif
			}
            else if (strcmp(next_endpoint, IOT_AGENT_TEST_ENDPOINT_DATASTORE_FS) == 0) {
				agent_status = iot_agent_datastore_fs_init(&datastore_fs, 0U, gszDatastoreFilename,
					&iot_agent_service_is_configuration_data_valid);
				AGENT_SUCCESS_OR_EXIT();

				agent_status = iot_agent_register_datastore(&iot_agent_context, &datastore_fs);
				AGENT_SUCCESS_OR_EXIT();

                IOT_AGENT_TEST_LOG(TEST_LOG_ID_REGISTER_ENDPOINT, "{ endpoint: '%s' }", IOT_AGENT_TEST_ENDPOINT_DATASTORE_FS);
			}
			else if (strcmp(next_endpoint, IOT_AGENT_TEST_ENDPOINT_DATASTORE_PLAIN) == 0) {
				agent_status = iot_agent_datastore_plain_init(&datastore_plain, 0U);
				AGENT_SUCCESS_OR_EXIT();

				agent_status = iot_agent_register_datastore(&iot_agent_context, &datastore_plain);
				AGENT_SUCCESS_OR_EXIT();

				IOT_AGENT_TEST_LOG(TEST_LOG_ID_REGISTER_ENDPOINT, "{ endpoint: '%s' }", IOT_AGENT_TEST_ENDPOINT_DATASTORE_PLAIN);
			}
		}
    }

	agent_status = iot_agent_datastore_plain_init(&edgelock2go_datastore, nxp_iot_DatastoreIdentifiers_DATASTORE_EDGELOCK2GO_ID);
	AGENT_SUCCESS_OR_EXIT();

	agent_status = iot_agent_utils_write_edgelock2go_datastore_from_env(&keystore, &edgelock2go_datastore);
	AGENT_SUCCESS_OR_EXIT();

	agent_status = iot_agent_set_edgelock2go_datastore(&iot_agent_context, &edgelock2go_datastore);
	AGENT_SUCCESS_OR_EXIT();

    //close SE session
	iot_agent_session_disconnect(&gex_sss_boot_ctx);

    iot_agent_test_synchronization_point();


	while (!terminated)
	{
        agent_status = iot_agent_update_device_configuration(&iot_agent_context, NULL);
		AGENT_SUCCESS_OR_EXIT();

		// Re-Open SE session
		IOT_AGENT_INFO("Re-establish connection to SE ...\n");
		agent_status = iot_agent_session_connect(&gex_sss_boot_ctx);
		AGENT_SUCCESS_OR_EXIT_MSG("Failed to re-connect to Secure Element.")

		// Reload the keystore - it could have been changed during provisioning.
		sss_status = sss_key_store_load(&gex_sss_boot_ctx.ks);
		SSS_SUCCESS_OR_EXIT_MSG("sss_key_store_load returned with 0x%04x", sss_status);

		if (iot_agent_is_service_configuration_data_valid(&iot_agent_context))
		{
			size_t number_of_services = iot_agent_get_number_of_services(&iot_agent_context);
			for (size_t i = 0U; i < number_of_services; i++)
			{
				agent_status = iot_agent_select_service_by_index(&iot_agent_context, i, &service_descriptor);
				AGENT_SUCCESS_OR_EXIT();

				char* client_certificate_str = pb_bytes_array_to_hex_str(service_descriptor.client_certificate);

				IOT_AGENT_TEST_LOG(TEST_LOG_ID_PROVISIONED_SERVICE, "{ service_id: '%" PRIu64 "', hostname: '%s', port: %d, client_cert: '%s' }",
					service_descriptor.identifier, service_descriptor.hostname, service_descriptor.port, client_certificate_str);

				free(client_certificate_str);
			}
		}

		//close SE session
		iot_agent_session_disconnect(&gex_sss_boot_ctx);
        //Clsoe session
	    ex_sss_session_close(&gex_sss_boot_ctx);

		iot_agent_test_synchronization_point();
	}

exit:
	iot_agent_free_service_descriptor(&service_descriptor);

	iot_agent_datastore_free(&edgelock2go_datastore);
	iot_agent_datastore_free(&datastore_fs);
	iot_agent_datastore_free(&datastore_plain);

	iot_agent_keystore_free(&keystore);

	IOT_AGENT_TEST_LOG(TEST_LOG_ID_TERMINATED, "{ }");
	return (int)agent_status;

}
