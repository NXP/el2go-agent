/*
 * Copyright 2018-2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "rtp/el2go_rtp.h"
#include "common/el2go_datastore.h"
#include "common/el2go_keystore.h"
#include "common/el2go_platform.h"
#include "rtp/el2go_rtp_config.h"

/* ========================================================================== */
/* Usage                                                                      */
/* ========================================================================== */

static void print_usage(const char *prog_name)
{
    printf("Usage: %s [options]\n", prog_name);
    printf("\n");
    printf("Options:\n");
    printf("  --hostname <hostname>   EdgeLock 2GO server hostname\n");
    printf("                          (default: %s)\n", EL2GO_RTP_EDGELOCK2GO_HOSTNAME);
    printf("  --port <port>           EdgeLock 2GO server port\n");
    printf("                          (default: %u)\n", EL2GO_RTP_EDGELOCK2GO_PORT);
    printf("  --help                  Print this help message\n");
    printf("\n");
}

/* ========================================================================== */
/* Argument parsing                                                           */
/* ========================================================================== */

typedef struct {
    const char *hostname;
    uint16_t port;
} demo_args_t;

static int parse_args(int argc, char **argv, demo_args_t *args)
{
    /* No defaults - NULL and 0 mean use compile-time constants */
    args->hostname = NULL;
    args->port = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0) {
            return -1;
        } else if (strcmp(argv[i], "--hostname") == 0) {
            if (i + 1 >= argc) {
                (void)fprintf(stderr, "Error: --hostname requires an argument\n");
                return -1;
            }
            args->hostname = argv[++i];
        } else if (strcmp(argv[i], "--port") == 0) {
            if (i + 1 >= argc) {
                (void)fprintf(stderr, "Error: --port requires an argument\n");
                return -1;
            }
            int port = atoi(argv[++i]);
            if (port <= 0 || port > 65535) {
                (void)fprintf(stderr, "Error: invalid port number: %s\n", argv[i]);
                return -1;
            }
            args->port = (uint16_t)port;
        } else {
            (void)fprintf(stderr, "Error: unknown option: %s\n", argv[i]);
            return -1;
        }
    }

    /* Hostname and port must be provided together */
    if (args->hostname != NULL && args->port == 0) {
        (void)fprintf(stderr, "Error: --port must be provided when --hostname is specified\n");
        return -1;
    }

    if (args->port != 0 && args->hostname == NULL) {
        (void)fprintf(stderr, "Error: --hostname must be provided when --port is specified\n");
        return -1;
    }

    return 0;
}

/* ========================================================================== */
/* Helpers                                                                    */
/* ========================================================================== */

static void print_uuid(const uint8_t *uuid, size_t uuid_len)
{
    size_t i = 0;

    printf("Device UUID (%zu bytes): 0x", uuid_len);
    for (i = 0; i < uuid_len; i++)
        printf("%02X", uuid[i]);
    printf("\n");
}

/* ========================================================================== */
/* Main                                                                       */
/* ========================================================================== */

int main(int argc, char **argv)
{
    unsigned int major = 0;
    unsigned int minor = 0;
    el2go_status_t status;
    el2go_rtp_ctx_t *agent_ctx = NULL;
    el2go_platform_ctx_t *platform_ctx = NULL;
    el2go_keystore_t keystore_ctx = { 0 };
    el2go_datastore_t datastore_ctx = { 0 };
    demo_args_t args = { 0 };
    uint8_t device_uuid[EL2GO_UUID_MAX_LEN];
    size_t uuid_size = 0;
    el2go_rtp_datastore_config_t el2go_config = { 0 };

    printf("EL2GO RTP Agent Demo\n");
    printf("====================\n\n");

    /* Parse command line arguments */
    if (parse_args(argc, argv, &args) != 0) {
        print_usage(argv[0]);
        return 1;
    }

    printf("Configuration:\n");
    printf("  Hostname: %s\n", args.hostname ? args.hostname : EL2GO_RTP_EDGELOCK2GO_HOSTNAME);
    printf("  Port:     %u\n", args.port ? args.port : EL2GO_RTP_EDGELOCK2GO_PORT);
    printf("\n");

    /* Initialize EL2GO RTP Agent */
    printf("Initializing EL2GO RTP Agent...\n");
    status = el2go_rtp_init(&agent_ctx);
    if (status != EL2GO_STATUS_SUCCESS) {
        printf("Failed to initialize EL2GO RTP Agent (status: %d)\n", status);
        return 1;
    }
    printf("EL2GO RTP Agent initialized successfully\n\n");

    /* Get and display EL2GO RTP Agent version */
    printf("Getting EL2GO RTP Agent version...\n");
    status = el2go_rtp_get_version(&major, &minor);
    if (status == EL2GO_STATUS_SUCCESS) {
        printf("EL2GO RTP Agent Version: %u.%u\n\n", major, minor);
    } else {
        printf("Failed to get EL2GO RTP Agent version (status: %d)\n", status);
        goto cleanup_agent;
    }

    /* Initialize platform */
    printf("Initializing platform...\n");
    status = el2go_platform_init(&platform_ctx);
    if (status != EL2GO_STATUS_SUCCESS) {
        printf("Failed to initialize platform (status: %d)\n", status);
        goto cleanup_agent;
    }
    printf("Platform initialized successfully\n\n");

    /* Get device UUID */
    printf("Getting device UUID...\n");
    status = el2go_platform_get_uuid(platform_ctx, device_uuid, sizeof(device_uuid), &uuid_size);
    if (status == EL2GO_STATUS_SUCCESS) {
        print_uuid(device_uuid, uuid_size);
        printf("\n");
    } else {
        printf("Failed to get device UUID (status: %d)\n", status);
        goto cleanup_platform;
    }

    /* Initialize keystore */
    printf("Initializing keystore (PSA type)...\n");
    status = el2go_keystore_init(EL2GO_RTP_EDGELOCK2GO_KEYSTORE_ID, platform_ctx, &keystore_ctx);
    if (status != EL2GO_STATUS_SUCCESS) {
        printf("Failed to initialize keystore (status: %d)\n", status);
        goto cleanup_platform;
    }
    printf("Keystore initialized successfully\n\n");

    /* Add keystore to agent */
    printf("Adding keystore to agent...\n");
    status = el2go_rtp_add_keystore(agent_ctx, &keystore_ctx);
    if (status != EL2GO_STATUS_SUCCESS) {
        printf("Failed to add keystore to agent (status: %d)\n", status);
        goto cleanup_keystore_free;
    }
    printf("Keystore added to agent successfully\n\n");

    /* Initialize datastore */
    printf("Initializing datastore (FS type)...\n");
    status = el2go_datastore_init(EL2GO_RTP_DATASTORE_EDGELOCK_ID, "el2go_datastore",
                                  EL2GO_DATASTORE_TYPE_FS, &datastore_ctx, NULL);
    if (status != EL2GO_STATUS_SUCCESS) {
        printf("Failed to initialize datastore (status: %d)\n", status);
        goto cleanup_keystore;
    }
    printf("Datastore initialized successfully\n\n");

    /* Add datastore to agent */
    printf("Adding datastore to agent...\n");
    status = el2go_rtp_add_datastore(agent_ctx, &datastore_ctx);
    if (status != EL2GO_STATUS_SUCCESS) {
        printf("Failed to add datastore to agent (status: %d)\n", status);
        goto cleanup_datastore_free;
    }
    printf("Datastore added to agent successfully\n\n");

    /* Configure EdgeLock 2GO communication parameters */
    printf("Configuring EdgeLock 2GO datastore...\n");
    el2go_config.hostname = args.hostname;
    el2go_config.port = args.port;
    el2go_config.certificate = NULL;
    status = el2go_rtp_datastore_el2go(&datastore_ctx, &keystore_ctx, &el2go_config);
    if (status != EL2GO_STATUS_SUCCESS) {
        printf("Failed to configure EdgeLock 2GO (status: %d)\n", status);
        goto cleanup_datastore;
    }
    printf("EdgeLock 2GO configured successfully\n\n");

    /* Provision device from EdgeLock 2GO server */
    printf("Provisioning device from EdgeLock 2GO server...\n");
    status = el2go_rtp_provision(agent_ctx, EL2GO_STATUS_ALWAYS);
    if (status != EL2GO_STATUS_SUCCESS) {
        printf("Failed to provision device (status: %d)\n", status);
        goto cleanup_datastore;
    }
    printf("Device provisioned successfully\n\n");

    /* Additional EL2GO RTP Agent functionality will be added here */

    printf("EL2GO RTP Agent demo completed successfully\n\n");

    /* Cleanup resources */
cleanup_datastore:
    el2go_rtp_remove_datastore(agent_ctx, &datastore_ctx);

cleanup_datastore_free:
    el2go_datastore_free(&datastore_ctx);

cleanup_keystore:
    el2go_rtp_remove_keystore(agent_ctx, &keystore_ctx);

cleanup_keystore_free:
    el2go_keystore_free(&keystore_ctx);

cleanup_platform:
    el2go_platform_free(&platform_ctx);

cleanup_agent:
    (void)el2go_rtp_free(&agent_ctx);

    return (status == EL2GO_STATUS_SUCCESS) ? 0 : 1;
}