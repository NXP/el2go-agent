// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright 2018-2026 NXP
 */

#include <stdio.h>
#include "el2go_agent.h"
#include "el2go_agent_datastore.h"
#include "el2go_agent_keystore.h"
#include "el2go_agent_platform.h"
#include "el2go_agent_config.h"

#define DEVICEID_LENGTH 16U

int main(int argc, char **argv)
{
	unsigned int major = 0;
	unsigned int minor = 0;
	el2go_agent_t status;
	el2go_agent_ctx_t *agent_ctx = NULL;
	el2go_agent_platform_ctx_t *platform_ctx = NULL;
	el2go_agent_keystore_t keystore_ctx = { 0 };
	el2go_agent_datastore_t datastore_ctx = { 0 };

	printf("NXP IoT Agent Demo\n");
	printf("==================\n\n");

	/* Initialize IoT Agent */
	printf("Initializing IoT Agent...\n");
	status = el2go_agent_init(&agent_ctx);
	if (status != EL2GO_AGENT_SUCCESS) {
		printf("Failed to initialize IoT Agent (status: %d)\n", status);
		return 1;
	}
	printf("IoT Agent initialized successfully\n\n");

	/* Get and display IoT Agent version */
	printf("Getting IoT Agent version...\n");
	status = el2go_agent_get_version(&major, &minor);

	if (status == EL2GO_AGENT_SUCCESS) {
		printf("IoT Agent Version: %u.%u\n\n", major, minor);
	} else {
		printf("Failed to get IoT Agent version (status: %d)\n",
		       status);
		return 1;
	}

	/* Initialize platform
	 * param_count and param_list must be forwarded to the lower-level SE05x Middleware library,
	 * as this is a requirement of its API that cannot be modified.
	 * While the demo application could be refactored to accept more
	 * user-friendly command-line parameters, the SE05x Middleware library still
	 * requires these parameters in its current format.
	 * Other platforms do not require any parameters.
	 */
	printf("Initializing platform...\n");
	el2go_agent_platform_config_t platform_config = { .param_count = argc,
							  .param_list = argv };
	status = el2go_agent_platform_init(&platform_config, &platform_ctx);
	if (status != EL2GO_AGENT_SUCCESS) {
		printf("Failed to initialize platform (status: %d)\n", status);
		goto cleanup_agent;
	}
	printf("Platform initialized successfully\n\n");

	/* Get device UUID - optional step */
	printf("Getting device UUID...\n");
	char device_uuid[DEVICEID_LENGTH] = { 0 };
	size_t uuid_size = sizeof(device_uuid);
	status =
		el2go_agent_get_device_uuid(agent_ctx, device_uuid, &uuid_size);
	if (status == EL2GO_AGENT_SUCCESS) {
		printf("Device UUID: %s (size: %zu)\n\n", device_uuid,
		       uuid_size);
	} else {
		printf("Failed to get device UUID (status: %d, required size: %zu)\n",
		       status, uuid_size);
		goto cleanup_platform;
	}

	/* Import claim code for device provisioning - optional step in demo */
	printf("Importing claim code...\n");
	const char *claimcode =
		"AAAA-BBBB-CCCC-DDDD-EEEE-FFFF"; /* Example claim code */
	status = el2go_agent_claimcode_import(platform_ctx, claimcode);
	if (status != EL2GO_AGENT_SUCCESS) {
		printf("Failed to import claim code (status: %d)\n", status);
		goto cleanup_platform;
	}
	printf("Claim code imported successfully\n\n");

	/* Initialize keystore */
	printf("Initializing keystore (PSA type)...\n");
	status = el2go_agent_keystore_init(EL2GO_AGENT_DATASTORE_EDGELOCK_ID,
					   EL2GO_AGENT_KEYSTORE_PSA,
					   platform_ctx, &keystore_ctx);
	if (status != EL2GO_AGENT_SUCCESS) {
		printf("Failed to initialize keystore (status: %d)\n", status);
		goto cleanup_platform;
	}
	printf("Keystore initialized successfully\n\n");

	/* Add keystore to agent */
	printf("Adding keystore to agent...\n");
	status = el2go_agent_keystore_add(agent_ctx, &keystore_ctx);
	if (status != EL2GO_AGENT_SUCCESS) {
		printf("Failed to add keystore to agent (status: %d)\n",
		       status);
		goto cleanup_keystore_free;
	}
	printf("Keystore added to agent successfully\n\n");

	/* Initialize datastore */
	printf("Initializing datastore (FS type)...\n");
	status = el2go_agent_datastore_init(EL2GO_AGENT_DATASTORE_EDGELOCK_ID,
					    "el2go_datastore",
					    EL2GO_AGENT_DATASTORE_TYPE_FS,
					    &datastore_ctx,
					    NULL); /* No validator for now */
	if (status != EL2GO_AGENT_SUCCESS) {
		printf("Failed to initialize datastore (status: %d)\n", status);
		goto cleanup_keystore;
	}
	printf("Datastore initialized successfully\n\n");

	/* Add datastore to agent */
	printf("Adding datastore to agent...\n");
	status = el2go_agent_datastore_add(agent_ctx, &datastore_ctx);
	if (status != EL2GO_AGENT_SUCCESS) {
		printf("Failed to add datastore to agent (status: %d)\n",
		       status);
		goto cleanup_datastore_free;
	}
	printf("Datastore added to agent successfully\n\n");

	/* Configure EdgeLock 2GO communication parameters */
	printf("Configuring EdgeLock 2GO datastore...\n");
	el2go_agent_el2go_config_t el2go_config = {
		.hostname = "edgelock2go.com",
		.port = 443,
		.certificate = NULL /* Use default certificate */
	};
	status = el2go_agent_datastore_el2go(&datastore_ctx, &keystore_ctx,
					     &el2go_config);
	if (status != EL2GO_AGENT_SUCCESS) {
		printf("Failed to configure EdgeLock 2GO (status: %d)\n",
		       status);
		goto cleanup_datastore;
	}
	printf("EdgeLock 2GO configured successfully\n\n");

	/* Provision device from EdgeLock 2GO server */
	printf("Provisioning device from EdgeLock 2GO server...\n");
	status = el2go_agent_provision(agent_ctx, EL2GO_AGENT_STATUS_ALWAYS);
	if (status != EL2GO_AGENT_SUCCESS) {
		printf("Failed to provision device (status: %d)\n", status);
		goto cleanup_datastore;
	}
	printf("Device provisioned successfully\n\n");

	/* Additional IoT Agent functionality will be added here */

	printf("IoT Agent demo completed successfully\n\n");

	/* Cleanup resources */
cleanup_datastore:
	printf("Removing datastore from agent...\n");
	el2go_agent_datastore_remove(agent_ctx, &datastore_ctx);
	goto cleanup_keystore;

cleanup_datastore_free:
	printf("Freeing datastore...\n");
	el2go_agent_datastore_free(&datastore_ctx);

cleanup_keystore:
	printf("Removing keystore from agent...\n");
	el2go_agent_keystore_remove(agent_ctx, &keystore_ctx);

cleanup_keystore_free:
	printf("Freeing keystore...\n");
	el2go_agent_keystore_free(&keystore_ctx);

cleanup_platform:
	printf("Cleaning up platform...\n");
	el2go_agent_platform_free(&platform_ctx);

cleanup_agent:
	printf("Cleaning up IoT Agent...\n");
	el2go_agent_free(&agent_ctx);

	printf("\nCleanup completed\n");
	return (status == EL2GO_AGENT_SUCCESS) ? 0 : 1;
}