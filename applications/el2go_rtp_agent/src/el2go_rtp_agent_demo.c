/*
 * Copyright 2018-2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <string.h>
#include <stdlib.h>

#include "rtp/el2go_rtp.h"
#include "common/el2go_datastore.h"
#include "common/el2go_keystore.h"
#include "common/el2go_platform.h"
#include "common/el2go_status.h"
#include "rtp/el2go_rtp_config.h"
#include "el2go_app_net.h"
#include "el2go_mqtt.h"
#include "osal.h"
#include "el2go_rtp_agent_log.h"
#include "el2go_app_time_measurement.h"

/* ========================================================================== */
/* UUID printing                                                               */
/* ========================================================================== */

static void print_uuid(const uint8_t *buf, size_t len)
{
    EL2GO_RTP_LOG_INFO("Device UUID (%zu bytes):", len);
    for (size_t i = 0U; i < len; i++) {
        printc("%02x", buf[i]);
    }
    printc("\r\n");
}

/* ========================================================================== */
/* Agent entry point                                                           */
/* ========================================================================== */

static int agent_start(int argc, const char *argv[])
{
    /* Runtime overrides (OTA agent style):
     *   argv[1]  EL2GO server hostname  (default: EL2GO_RTP_EDGELOCK2GO_HOSTNAME)
     *   argv[2]  EL2GO server port      (default: EL2GO_RTP_EDGELOCK2GO_PORT)
     *   argv[3]  Claim code string      (default: import from flash)
     * All arguments are optional; compile-time Kconfig values are used when absent.
     */
    const char *hostname = EL2GO_RTP_EDGELOCK2GO_HOSTNAME;
    uint16_t port = EL2GO_RTP_EDGELOCK2GO_PORT;
    const char *claimcode = NULL;

    if (argc > 1)
        hostname = argv[1];
    if (argc > 2) {
        int p = atoi(argv[2]);
        if (p > 0 && p <= 65535)
            port = (uint16_t)p;
    }
    if (argc > 3)
        claimcode = argv[3];

    el2go_status_t status;
    el2go_rtp_ctx_t *agent_ctx = NULL;
    el2go_platform_ctx_t *platform_ctx = NULL;
    el2go_keystore_t keystore_ctx = { 0 };
    el2go_datastore_t datastore_ctx = { 0 };
    void *report = NULL;
    int rc = 0;
    unsigned int major = 0U;
    unsigned int minor = 0U;
    unsigned int patch = 0U;

    el2go_time_ctx_t demo_time = { 0 };
    el2go_time_ctx_t phase_time = { 0 };
    el2go_time_t timing = { 0 };

    EL2GO_RTP_LOG_ALWAYS("\nEL2GO RTP Agent Demo\n");
    EL2GO_RTP_LOG_ALWAYS("====================\n\n");
    EL2GO_RTP_LOG_INFO("Hostname : %s", hostname);
    EL2GO_RTP_LOG_INFO("Port     : %u", port);

    el2go_time_init(&demo_time);

    /* ---------------------------------------------------------------------- */
    /* Network initialization                                                  */
    /* ---------------------------------------------------------------------- */
    rc = el2go_app_net_init();
    if (rc != 0) {
        EL2GO_RTP_LOG_ERROR("Network init failed (%d)", rc);
        return rc;
    }
    EL2GO_RTP_LOG_INFO("Network initialized");

    /* ---------------------------------------------------------------------- */
    /* Platform initialization                                                 */
    /* ---------------------------------------------------------------------- */
    status = el2go_platform_init(&platform_ctx);
    if (status != EL2GO_STATUS_SUCCESS) {
        EL2GO_RTP_LOG_ERROR("Platform init failed (status: %d)", status);
        return -1;
    }
    EL2GO_RTP_LOG_INFO("Platform initialized");

    /* ---------------------------------------------------------------------- */
    /* EL2GO RTP Agent initialization                                          */
    /* ---------------------------------------------------------------------- */
    status = el2go_rtp_init(&agent_ctx);
    if (status != EL2GO_STATUS_SUCCESS) {
        EL2GO_RTP_LOG_ERROR("RTP agent init failed (status: %d)", status);
        goto cleanup_platform;
    }
    EL2GO_RTP_LOG_INFO("RTP agent initialized");

    status = el2go_rtp_get_version(&major, &minor, &patch);
    if (status == EL2GO_STATUS_SUCCESS)
        EL2GO_RTP_LOG_INFO("EL2GO RTP Agent Version: %u.%u.%u", major, minor, patch);

    /* ---------------------------------------------------------------------- */
    /* Keystore initialization                                                 */
    /* ---------------------------------------------------------------------- */
    status = el2go_keystore_init(EL2GO_RTP_EDGELOCK2GO_KEYSTORE_ID, platform_ctx, &keystore_ctx);
    if (status != EL2GO_STATUS_SUCCESS) {
        EL2GO_RTP_LOG_ERROR("Keystore init failed (status: %d)", status);
        goto cleanup_agent;
    }
    EL2GO_RTP_LOG_INFO("Keystore initialized");

    /* ---------------------------------------------------------------------- */
    /* Claimcode import (timed)                                                */
    /* ---------------------------------------------------------------------- */
    el2go_time_init(&phase_time);

    if (claimcode != NULL) {
        /* Runtime claimcode provided via argv[3] or CONFIG_BOOTARGS */
        status = el2go_keystore_import_claimcode(&keystore_ctx, claimcode, strlen(claimcode));
        if (status != EL2GO_STATUS_SUCCESS) {
            EL2GO_RTP_LOG_ERROR("Claimcode import failed (status: %d)", status);
            goto cleanup_keystore_free;
        }
        EL2GO_RTP_LOG_INFO("Claimcode imported from argument");
    } else {
        /* No runtime claimcode -- read from flash (Zephyr); no-op weak stub on Linux */
        status = el2go_keystore_import_claimcode_from_flash(&keystore_ctx);
        if (status != EL2GO_STATUS_SUCCESS) {
            EL2GO_RTP_LOG_ERROR("Claimcode flash import failed (status: %d)", status);
            goto cleanup_keystore_free;
        }
        EL2GO_RTP_LOG_INFO("Claimcode imported from flash");
    }

    el2go_time_conclude(&phase_time);
    timing.claimcode_inject_time = el2go_time_get_ms(&phase_time);
    el2go_time_log_phase("CLAIMCODE_INJECT_TIME", timing.claimcode_inject_time);

    /* ---------------------------------------------------------------------- */
    /* Device UUID                                                             */
    /* ---------------------------------------------------------------------- */
    {
        uint8_t uuid_buf[EL2GO_UUID_MAX_LEN] = { 0 };
        size_t uuid_len = 0U;

        status = el2go_platform_get_uuid(platform_ctx, uuid_buf, sizeof(uuid_buf), &uuid_len);
        if (status == EL2GO_STATUS_SUCCESS)
            print_uuid(uuid_buf, uuid_len);
        else
            EL2GO_RTP_LOG_INFO("Could not get device UUID (status: %d)", status);
    }

    /* ---------------------------------------------------------------------- */
    /* Add keystore to agent                                                   */
    /* ---------------------------------------------------------------------- */
    status = el2go_rtp_add_keystore(agent_ctx, &keystore_ctx);
    if (status != EL2GO_STATUS_SUCCESS) {
        EL2GO_RTP_LOG_ERROR("Add keystore failed (status: %d)", status);
        goto cleanup_keystore_free;
    }
    EL2GO_RTP_LOG_INFO("Keystore added to agent");

    /* ---------------------------------------------------------------------- */
    /* Datastore initialization                                                */
    /* ---------------------------------------------------------------------- */
    status = el2go_datastore_init(EL2GO_RTP_DATASTORE_EDGELOCK_ID, "el2go_datastore",
                                  EL2GO_DATASTORE_TYPE_PLAIN, &datastore_ctx, NULL);
    if (status != EL2GO_STATUS_SUCCESS) {
        EL2GO_RTP_LOG_ERROR("Datastore init failed (status: %d)", status);
        goto cleanup_keystore;
    }
    EL2GO_RTP_LOG_INFO("Datastore initialized");

    /* ---------------------------------------------------------------------- */
    /* Add datastore to agent                                                  */
    /* ---------------------------------------------------------------------- */
    status = el2go_rtp_add_datastore(agent_ctx, &datastore_ctx);
    if (status != EL2GO_STATUS_SUCCESS) {
        EL2GO_RTP_LOG_ERROR("Add datastore failed (status: %d)", status);
        goto cleanup_datastore_free;
    }
    EL2GO_RTP_LOG_INFO("Datastore added to agent");

    /* ---------------------------------------------------------------------- */
    /* EdgeLock 2GO server configuration                                       */
    /* ---------------------------------------------------------------------- */
    {
        el2go_rtp_datastore_config_t el2go_config = { .hostname = hostname,
                                                      .port = port,
                                                      .certificate = NULL };

        status = el2go_rtp_datastore_el2go(&datastore_ctx, &keystore_ctx, &el2go_config);
        if (status != EL2GO_STATUS_SUCCESS) {
            EL2GO_RTP_LOG_ERROR("EL2GO datastore config failed (status: %d)", status);
            goto cleanup_datastore;
        }
        EL2GO_RTP_LOG_INFO("EL2GO server configured: %s:%u", hostname, port);
    }

    /* Capture init_time -- everything up to this point */
    el2go_time_conclude(&demo_time);
    timing.init_time = el2go_time_get_ms(&demo_time) - timing.claimcode_inject_time;
    el2go_time_log_phase("DEVICE_INIT_TIME", timing.init_time);

    /* ---------------------------------------------------------------------- */
    /* Provisioning (timed)                                                    */
    /* ---------------------------------------------------------------------- */
    EL2GO_RTP_LOG_INFO("Provisioning from EdgeLock 2GO...");

    el2go_time_init(&phase_time);
    status = el2go_rtp_provision(agent_ctx, &report);
    el2go_rtp_print_status_report(report);
    el2go_rtp_free_status_report(&report);
    el2go_time_conclude(&phase_time);
    timing.provision_time = el2go_time_get_ms(&phase_time);
    el2go_time_log_phase("PROVISION_TIME", timing.provision_time);

    if (status != EL2GO_STATUS_SUCCESS) {
        EL2GO_RTP_LOG_ERROR("Provisioning failed (status: %d)", status);
        goto cleanup_datastore;
    }
    EL2GO_RTP_LOG_INFO("Provisioning completed successfully");

    /* ---------------------------------------------------------------------- */
    /* MQTT credential verification (timed)                                    */
    /* ---------------------------------------------------------------------- */
    el2go_time_init(&phase_time);
    rc = el2go_mqtt_verify(&keystore_ctx);
    el2go_time_conclude(&phase_time);
    timing.mqtt_verify_time = el2go_time_get_ms(&phase_time);
    el2go_time_log_phase("MQTT_VERIFY_TIME", timing.mqtt_verify_time);

    if (rc != 0)
        EL2GO_RTP_LOG_ERROR("MQTT verify failed (%d)", rc);
    else
        EL2GO_RTP_LOG_INFO("EL2GO RTP Agent demo completed successfully");

    /* ---------------------------------------------------------------------- */
    /* Final timing report                                                     */
    /* ---------------------------------------------------------------------- */
    el2go_time_conclude(&demo_time);
    timing.total_time = el2go_time_get_ms(&demo_time);
    el2go_log_performance_timing(&timing);

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
