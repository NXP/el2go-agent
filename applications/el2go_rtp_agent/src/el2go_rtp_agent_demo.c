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
#include "common/el2go_status.h"
#include "rtp/el2go_rtp_config.h"
#include "osal.h"
#include "el2go_app_net.h"

#include "keystores/keystore_priv.h"
#include "mqtt/el2go_mqtt.h"

/* ========================================================================== */
/* UUID printing                                                               */
/* ========================================================================== */

static void print_uuid(const uint8_t *buf, size_t len)
{
    osal_printf(DBG_LEVEL_INFO, "Device UUID (%zu bytes):", len);
    osal_hex_dump(DBG_LEVEL_INFO, buf, len);
}

/* ========================================================================== */
/* Agent entry point                                                           */
/* ========================================================================== */

static int agent_start(int argc, const char *argv[])
{
    (void)argc;
    (void)argv;

    el2go_status_t status;
    el2go_rtp_ctx_t *agent_ctx = NULL;
    el2go_platform_ctx_t *platform_ctx = NULL;
    el2go_keystore_t keystore_ctx = { 0 };
    el2go_datastore_t datastore_ctx = { 0 };
    void *report = NULL;
    int rc = 0;
    unsigned int major = 0;
    unsigned int minor = 0;

    osal_printf_always("\nEL2GO RTP Agent Demo\n");
    osal_printf_always("====================\n\n");

    /* Initialize network */
    rc = el2go_app_net_init();
    if (rc != 0) {
        osal_printf(DBG_LEVEL_ERROR, "Network initialization failed (%d)", rc);
        return rc;
    }

    /* Initialize platform */
    status = el2go_platform_init(&platform_ctx);
    if (status != EL2GO_STATUS_SUCCESS) {
        osal_printf(DBG_LEVEL_ERROR, "Platform init failed (status: %d)", status);
        return -1;
    }
    osal_printf(DBG_LEVEL_INFO, "Platform initialized");

    /* Initialize EL2GO RTP Agent */
    status = el2go_rtp_init(&agent_ctx);
    if (status != EL2GO_STATUS_SUCCESS) {
        osal_printf(DBG_LEVEL_ERROR, "RTP agent init failed (status: %d)", status);
        goto cleanup_platform;
    }
    osal_printf(DBG_LEVEL_INFO, "RTP agent initialized");

    /* Get and display EL2GO RTP Agent version */
    status = el2go_rtp_get_version(&major, &minor);
    if (status == EL2GO_STATUS_SUCCESS) {
        osal_printf(DBG_LEVEL_INFO, "EL2GO RTP Agent Version: %u.%u", major, minor);
    } else {
        osal_printf(DBG_LEVEL_INFO, "Could not get RTP agent version (status: %d)", status);
    }

    /* Initialize keystore */
    status = el2go_keystore_init(EL2GO_RTP_EDGELOCK2GO_KEYSTORE_ID, platform_ctx, &keystore_ctx);
    if (status != EL2GO_STATUS_SUCCESS) {
        osal_printf(DBG_LEVEL_ERROR, "Keystore init failed (status: %d)", status);
        goto cleanup_agent;
    }
    osal_printf(DBG_LEVEL_INFO, "Keystore initialized");

    /* Import claimcode from flash into PSA ITS if not already present */
    status = el2go_keystore_import_claimcode_from_flash(&keystore_ctx);
    if (status != EL2GO_STATUS_SUCCESS) {
        osal_printf(DBG_LEVEL_ERROR, "Claimcode import failed (status: %d)", status);
        goto cleanup_keystore_free;
    }
    osal_printf(DBG_LEVEL_INFO, "Claimcode imported from flash");

    /* Get device UUID */
    {
        uint8_t uuid_buf[EL2GO_UUID_MAX_LEN] = { 0 };
        size_t uuid_len = 0;

        status = el2go_platform_get_uuid(platform_ctx, uuid_buf, sizeof(uuid_buf), &uuid_len);
        if (status == EL2GO_STATUS_SUCCESS) {
            print_uuid(uuid_buf, uuid_len);
        } else {
            osal_printf(DBG_LEVEL_INFO, "Could not get device UUID (status: %d)", status);
        }
    }

    /* Add keystore to agent */
    status = el2go_rtp_add_keystore(agent_ctx, &keystore_ctx);
    if (status != EL2GO_STATUS_SUCCESS) {
        osal_printf(DBG_LEVEL_ERROR, "Add keystore failed (status: %d)", status);
        goto cleanup_keystore_free;
    }

    /* Initialize datastore */
    status = el2go_datastore_init(EL2GO_RTP_DATASTORE_EDGELOCK_ID, "el2go_datastore",
                                  EL2GO_DATASTORE_TYPE_PLAIN, &datastore_ctx, NULL);
    if (status != EL2GO_STATUS_SUCCESS) {
        osal_printf(DBG_LEVEL_ERROR, "Datastore init failed (status: %d)", status);
        goto cleanup_keystore;
    }
    osal_printf(DBG_LEVEL_INFO, "Datastore initialized");

    /* Add datastore to agent */
    status = el2go_rtp_add_datastore(agent_ctx, &datastore_ctx);
    if (status != EL2GO_STATUS_SUCCESS) {
        osal_printf(DBG_LEVEL_ERROR, "Add datastore failed (status: %d)", status);
        goto cleanup_datastore_free;
    }

    /* Configure EdgeLock 2GO server connection */

    el2go_rtp_datastore_config_t el2go_config = { .hostname = EL2GO_RTP_EDGELOCK2GO_HOSTNAME,
                                                  .port = EL2GO_RTP_EDGELOCK2GO_PORT,
                                                  .certificate = NULL };

    status = el2go_rtp_datastore_el2go(&datastore_ctx, &keystore_ctx, &el2go_config);
    if (status != EL2GO_STATUS_SUCCESS) {
        osal_printf(DBG_LEVEL_ERROR, "EL2GO datastore config failed (status: %d)", status);
        goto cleanup_datastore;
    }
    osal_printf(DBG_LEVEL_INFO, "EL2GO server configured: %s:%u", EL2GO_RTP_EDGELOCK2GO_HOSTNAME,
                EL2GO_RTP_EDGELOCK2GO_PORT);

    /* Provision device from EdgeLock 2GO */
    osal_printf(DBG_LEVEL_INFO, "Provisioning from EdgeLock 2GO...");
    status = el2go_rtp_provision(agent_ctx, &report);
    el2go_rtp_print_status_report(report);
    el2go_rtp_free_status_report(&report);

    if (status != EL2GO_STATUS_SUCCESS) {
        osal_printf(DBG_LEVEL_ERROR, "Provisioning failed (status: %d)", status);
        goto cleanup_datastore;
    }
    osal_printf(DBG_LEVEL_INFO, "Provisioning completed successfully");

    /* Verify provisioned MQTT credentials by connecting to the broker */
    rc = el2go_mqtt_verify(&keystore_ctx);
    if (rc != 0) {
        osal_printf(DBG_LEVEL_ERROR, "MQTT verify failed (%d)", rc);
    } else {
        osal_printf(DBG_LEVEL_INFO, "EL2GO RTP Agent demo completed successfully");
    }

cleanup_datastore:
    el2go_rtp_remove_datastore(agent_ctx, &datastore_ctx);

cleanup_datastore_free:
    el2go_datastore_free(&datastore_ctx);

cleanup_keystore:
    el2go_rtp_remove_keystore(agent_ctx, &keystore_ctx);

cleanup_keystore_free:
    el2go_keystore_free(&keystore_ctx);

cleanup_agent:
    (void)el2go_rtp_free(&agent_ctx);

cleanup_platform:
    el2go_platform_free(&platform_ctx);

    return (status == EL2GO_STATUS_SUCCESS && rc == 0) ? 0 : -1;
}

/* ========================================================================== */
/* Main                                                                        */
/* ========================================================================== */

int main(int argc, const char *argv[])
{
    return osal_start_task(agent_start, argc, argv);
}
