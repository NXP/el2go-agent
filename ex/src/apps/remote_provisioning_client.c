/*
 * Copyright 2020, 2021 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iot_agent_rtp_client.h>

const char* hostname = "127.0.0.1";
const char* port = "7050";

#if defined(USE_RTOS) && (USE_RTOS == 1)
rtos_arguments_t server;
#endif

int main(int argc, const char *argv[])
{
#if defined(USE_RTOS) && (USE_RTOS == 1)
    server.hostname = hostname;
    server.port = port;

    return remote_provisioning_init_rtos(&server);
#else
    if (argc > 1) {
        if (strcmp(argv[1], "-help") == 0)
        {
            printf("Usage: Default host and port is set to %s %s\n", hostname, port);
            printf("To run with default Host and Port: \n\tremote_provisioning_client\n");
            printf("Set Host and with default port: \n\tremote_provisioning_client 1.1.1.1\n");
            printf("Set both Host and port: \n\tremote_provisioning_client 1.1.1.1 7060\n");
            return -1;
        }
        hostname = argv[1];
    }
    if (argc > 2) {
        port = argv[2];
    }

    return remote_provisioning_start(hostname, port);
#endif
}


