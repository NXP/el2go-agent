/*
 * Copyright 2018-2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define UUID_DECIMAL_STRING_SIZE 44U

#include "rtp/el2go_rtp.h"
#include "common/el2go_datastore.h"
#include "common/el2go_keystore.h"
#include "common/el2go_platform.h"
#include "common/el2go_status.h"
#include "rtp/el2go_rtp_config.h"
#include "rtp/el2go_rtp_timing.h"
#include "el2go_app_net.h"
#include "el2go_mqtt.h"
#include "osal.h"
#include "el2go_rtp_agent_log.h"
#include "el2go_rtp_agent_config.h"
#include "el2go_app_time_measurement.h"

/* ========================================================================== */
/* UUID printing                                                               */
/* ========================================================================== */

static void print_uuid_decimal(const uint8_t *buf, size_t len)
{
    /* Convert raw bytes -> hex string, then hex string -> single decimal integer.
     * Matches the old iot_agent_print_uid_integer() algorithm exactly. */
    char hexString[UUID_DECIMAL_STRING_SIZE + 1U];
    char decimalString[UUID_DECIMAL_STRING_SIZE + 1U];
    uint32_t weightValueArray[UUID_DECIMAL_STRING_SIZE] = { 0U };
    uint32_t decimalDigitWeightedSum[UUID_DECIMAL_STRING_SIZE] = { 0U };
    size_t hexLen = 0U;

    if (!buf || len == 0U)
        return;

    /* Build uppercase hex string from raw bytes */
    hexLen = len * 2U;
    if (hexLen > UUID_DECIMAL_STRING_SIZE)
        hexLen = UUID_DECIMAL_STRING_SIZE;
    for (size_t i = 0U; i < len && (i * 2U + 1U) < sizeof(hexString); i++)
        (void)snprintf(hexString + (i * 2U), 3U, "%02X", buf[i]);
    hexString[hexLen] = '\0';

    /* Weighted-sum hex-to-decimal conversion */
    weightValueArray[0] = 1U;
    memset(decimalString, '0', UUID_DECIMAL_STRING_SIZE);
    decimalString[UUID_DECIMAL_STRING_SIZE] = '\0';

    for (size_t i = 0U; i < hexLen; i++) {
        for (uint8_t j = 0U; j < UUID_DECIMAL_STRING_SIZE; j++) {
            uint32_t charWeightedContrib = 0U;
            unsigned char pickChar = (unsigned char)hexString[hexLen - 1U - i];
            if (pickChar >= '0' && pickChar <= '9')
                charWeightedContrib = (uint32_t)(pickChar - '0');
            else if (pickChar >= 'A' && pickChar <= 'F')
                charWeightedContrib = (uint32_t)(pickChar - 'A') + 10U;
            else if (pickChar >= 'a' && pickChar <= 'f')
                charWeightedContrib = (uint32_t)(pickChar - 'a') + 10U;
            charWeightedContrib *= weightValueArray[j];
            decimalDigitWeightedSum[j] += charWeightedContrib;
        }
        uint32_t rem = 0U;
        for (uint8_t k = 0U; k < UUID_DECIMAL_STRING_SIZE; k++) {
            weightValueArray[k] = rem + (weightValueArray[k] << 4);
            rem = weightValueArray[k] / 10U;
            weightValueArray[k] %= 10U;
        }
    }

    /* Accumulate weighted sums into decimal string */
    {
        uint32_t rem = 0U;
        for (uint8_t i = 0U; i < UUID_DECIMAL_STRING_SIZE; i++) {
            uint8_t index = UUID_DECIMAL_STRING_SIZE - 1U - i;
            decimalString[index] += (char)((rem + decimalDigitWeightedSum[i]) % 10U);
            rem = (rem + decimalDigitWeightedSum[i]) / 10U;
        }
    }

    /* Skip leading zeros (keep at least one digit) */
    const char *printedString = decimalString;
    while (*printedString == '0' && *(printedString + 1) != '\0')
        printedString++;

    EL2GO_RTP_LOG_INFO("UID in decimal format: %s", printedString);
}

static void print_uuid_hex(const uint8_t *buf, size_t len)
{
    char hexString[(UUID_DECIMAL_STRING_SIZE) + 1U] = { 0 };
    for (size_t i = 0U; i < len && (i * 2U + 1U) < sizeof(hexString); i++)
        (void)snprintf(hexString + (i * 2U), 3U, "%02X", buf[i]);
    EL2GO_RTP_LOG_INFO("UID in hex format: %s", hexString);
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
    el2go_time_ctx_t network_time = { 0 };
    el2go_time_ctx_t phase_time = { 0 };
    el2go_time_t timing = { 0 };

    EL2GO_RTP_LOG_DEBUG("EL2GO RTP Agent Demo");
    EL2GO_RTP_LOG_DEBUG("Hostname : %s", hostname);
    EL2GO_RTP_LOG_DEBUG("Port     : %u", port);

    el2go_time_init(&demo_time);
    el2go_time_init(&network_time);

    /* ---------------------------------------------------------------------- */
    /* Network initialization                                                  */
    /* ---------------------------------------------------------------------- */
    rc = el2go_app_net_init();
    if (rc != 0) {
        EL2GO_RTP_LOG_ERROR("Network init failed (%d)", rc);
        return rc;
    }
    el2go_time_conclude(&network_time);
    EL2GO_RTP_LOG_DEBUG("Network initialized");

    /* ---------------------------------------------------------------------- */
    /* Platform initialization                                                 */
    /* ---------------------------------------------------------------------- */
    status = el2go_platform_init(&platform_ctx);
    if (status != EL2GO_STATUS_SUCCESS) {
        EL2GO_RTP_LOG_ERROR("Platform init failed (status: %d)", status);
        return -1;
    }
    EL2GO_RTP_LOG_DEBUG("Platform initialized");

    /* ---------------------------------------------------------------------- */
    /* EL2GO RTP Agent initialization                                          */
    /* ---------------------------------------------------------------------- */
    status = el2go_rtp_init(&agent_ctx);
    if (status != EL2GO_STATUS_SUCCESS) {
        EL2GO_RTP_LOG_ERROR("RTP agent init failed (status: %d)", status);
        goto cleanup_platform;
    }
    EL2GO_RTP_LOG_DEBUG("RTP agent initialized");
    (void)el2go_rtp_enable_timing(agent_ctx);

    status = el2go_rtp_get_version(&major, &minor, &patch);
    if (status == EL2GO_STATUS_SUCCESS) {
        EL2GO_RTP_LOG_DEBUG("EL2GO RTP Agent Version: %u.%u.%u", major, minor, patch);
    }

    /* ---------------------------------------------------------------------- */
    /* Keystore initialization                                                 */
    /* ---------------------------------------------------------------------- */
    status = el2go_keystore_init(EL2GO_RTP_EDGELOCK2GO_KEYSTORE_ID, platform_ctx, &keystore_ctx);
    if (status != EL2GO_STATUS_SUCCESS) {
        EL2GO_RTP_LOG_ERROR("Keystore init failed (status: %d)", status);
        goto cleanup_agent;
    }
    EL2GO_RTP_LOG_DEBUG("Keystore initialized");

    /* Capture init_time -- split into DEVICE_INIT_TIME (network) and AGENT_INIT_TIME (agent setup).*/
    el2go_time_conclude(&demo_time);
    timing.device_init_time = el2go_time_get_ms(&network_time);
    timing.init_time =
        el2go_time_get_ms(&demo_time) - timing.device_init_time - timing.claimcode_inject_time;
    el2go_time_log_phase("DEVICE_INIT_TIME", timing.device_init_time);

    EL2GO_RTP_LOG_INFO("Start");

    /* ---------------------------------------------------------------------- */
    /* Claimcode import (timed)                                                */
    /* ---------------------------------------------------------------------- */
    el2go_time_init(&phase_time);

    if (EL2GO_RTP_CLAIMCODE_INJECT_ENABLED) {
        if (claimcode != NULL) {
            /* Runtime claimcode provided via argv[3] or CONFIG_BOOTARGS */
            status = el2go_keystore_import_claimcode(&keystore_ctx, claimcode, strlen(claimcode));
            if (status != EL2GO_STATUS_SUCCESS) {
                EL2GO_RTP_LOG_ERROR("Claimcode import failed (status: %d)", status);
                goto cleanup_keystore_free;
            }
            EL2GO_RTP_LOG_INFO("Claimcode imported from argument");
        } else {
            status = el2go_keystore_import_claimcode_from_flash(&keystore_ctx);
            if (status != EL2GO_STATUS_SUCCESS) {
                EL2GO_RTP_LOG_ERROR("Claimcode flash import failed (status: %d)", status);
                goto cleanup_keystore_free;
            }
        }

        el2go_time_conclude(&phase_time);
        timing.claimcode_inject_time = el2go_time_get_ms(&phase_time);
        el2go_time_log_phase("CLAIMCODE_INJECT_TIME", timing.claimcode_inject_time);
    }

    /* ---------------------------------------------------------------------- */
    /* Add keystore to agent                                                   */
    /* ---------------------------------------------------------------------- */
    status = el2go_rtp_add_keystore(agent_ctx, &keystore_ctx);
    if (status != EL2GO_STATUS_SUCCESS) {
        EL2GO_RTP_LOG_ERROR("Add keystore failed (status: %d)", status);
        goto cleanup_keystore_free;
    }
    EL2GO_RTP_LOG_DEBUG("Keystore added to agent");

    /* ---------------------------------------------------------------------- */
    /* Datastore initialization                                                */
    /* ---------------------------------------------------------------------- */
    status = el2go_datastore_init(EL2GO_RTP_DATASTORE_EDGELOCK_ID, "el2go_datastore",
                                  EL2GO_DATASTORE_TYPE_PLAIN, &datastore_ctx, NULL);
    if (status != EL2GO_STATUS_SUCCESS) {
        EL2GO_RTP_LOG_ERROR("Datastore init failed (status: %d)", status);
        goto cleanup_keystore;
    }
    EL2GO_RTP_LOG_DEBUG("Datastore initialized");

    /* ---------------------------------------------------------------------- */
    /* Add datastore to agent                                                  */
    /* ---------------------------------------------------------------------- */
    status = el2go_rtp_add_datastore(agent_ctx, &datastore_ctx);
    if (status != EL2GO_STATUS_SUCCESS) {
        EL2GO_RTP_LOG_ERROR("Add datastore failed (status: %d)", status);
        goto cleanup_datastore_free;
    }
    EL2GO_RTP_LOG_DEBUG("Datastore added to agent");

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
        EL2GO_RTP_LOG_DEBUG("EL2GO server configured: %s:%u", hostname, port);
    }

    /* ---------------------------------------------------------------------- */
    /* Device UUID                                                             */
    /* ---------------------------------------------------------------------- */
    {
        uint8_t uuid_buf[EL2GO_UUID_MAX_LEN] = { 0 };
        size_t uuid_len = 0U;

        status = el2go_platform_get_uuid(platform_ctx, uuid_buf, sizeof(uuid_buf), &uuid_len);
        if (status == EL2GO_STATUS_SUCCESS) {
            print_uuid_hex(uuid_buf, uuid_len);
            print_uuid_decimal(uuid_buf, uuid_len);
        } else
            EL2GO_RTP_LOG_INFO("Could not get device UUID (status: %d)", status);
    }

    /* ---------------------------------------------------------------------- */
    /* Provisioning (timed)                                                   */
    /* ---------------------------------------------------------------------- */
    EL2GO_RTP_LOG_INFO("Updating device configuration from [%s]:[%u].", hostname, port);

    el2go_time_init(&phase_time);
    status = el2go_rtp_provision(agent_ctx, &report);
    el2go_rtp_print_status_report(report);
    el2go_rtp_free_status_report(&report);
    el2go_time_conclude(&phase_time);
    timing.provision_time = el2go_time_get_ms(&phase_time);
    /* Retrieve sub-phase timings from library via API.
     * command_txrx_ms has no equivalent in PSA/ELS PKC builds 
     */
    {
        el2go_rtp_timing_t lib_timing = { 0 };
        if (el2go_rtp_get_timing(agent_ctx, &lib_timing) == EL2GO_STATUS_SUCCESS) {
            timing.tls_prep_ms = lib_timing.tls_prep_ms;
            timing.network_connect_ms = lib_timing.network_connect_ms;
            timing.crl_ms = lib_timing.crl_ms;
        }
    }

    if (status != EL2GO_STATUS_SUCCESS) {
        EL2GO_RTP_LOG_ERROR("Provisioning failed (status: %d)", status);
        goto cleanup_datastore;
    }
    EL2GO_RTP_LOG_DEBUG("Provisioning completed successfully");

    /* ---------------------------------------------------------------------- */
    /* Final timing report                                                    */
    /* ---------------------------------------------------------------------- */
    el2go_time_conclude(&demo_time);
    timing.total_time = el2go_time_get_ms(&demo_time);
    el2go_log_performance_timing(&timing);

    /* ---------------------------------------------------------------------- */
    /* MQTT credential verification (timed)                                   */
    /* ---------------------------------------------------------------------- */
    if (EL2GO_RTP_MQTT_VERIFY_ENABLED) {
        rc = el2go_mqtt_verify(&keystore_ctx);
        if (rc != 0) {
            EL2GO_RTP_LOG_ERROR("MQTT verify failed (%d)", rc);
        }
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
