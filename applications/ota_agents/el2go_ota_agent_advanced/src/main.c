/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

/*
 * Advanced OTA agent sample.
 *
 * Builds on the core agent flow by adding a scheduler with a configurable poll
 * cadence, exponential backoff, a blackout/defer policy, download and status
 * retries, and a network-up trigger. This entry point performs one-time
 * initialization (FWUAL, networking, time, credentials, and the OTA context),
 * reconciles any interrupted update from a previous boot, then hands control to
 * the scheduler which drives periodic update checks.
 */

#include "updater.h"
#include "scheduler.h"

#include "fwual/fwual.h"
#include "ota/el2go_ota_lib.h"
#include "ota/el2go_ota_certificates.h"

#include "el2go_app_net.h"
#include "el2go_app_time.h"
#include "el2go_app_sys.h"

#include "el2go_ota_diag.h"

#include <stdlib.h>

/**
 * @brief Scheduler callback that runs one update check.
 *
 * Invoked by the scheduler when a check is due; forwards to updater_run_check().
 *
 * @param[in] user_data  Pointer to the shared updater_ctx_t.
 */
static void on_scheduler_fire(void *user_data)
{
    updater_ctx_t *updater = (updater_ctx_t *)user_data;
    updater_run_check(updater);
}

/**
 * @brief Main time syncronization loop.
 *
 * Tries to syncronze the time up to the configured nubmer of attempts.
 *
 */
static void wait_for_time_sync(void)
{
    int cycle = -1;

    for (cycle = 0; cycle < CONFIG_EL2GO_OTA_ADV_TIME_SYNC_MAX_CYCLES; cycle++) {
        if (el2go_app_time_get_hour_of_day() >= 0) {
            break;
        }

        OTA_DIAG_INFO("waiting for time sync before connect (%d/%d)...", cycle + 1,
                      CONFIG_EL2GO_OTA_ADV_TIME_SYNC_MAX_CYCLES);
        el2go_app_sys_sleep_ms(CONFIG_EL2GO_OTA_ADV_TIME_SYNC_RETRY_DELAY_MS);
        el2go_app_time_sync();
    }
    OTA_DIAG_WARN("time sync unavailable - proceeding (cert checks/blackout degraded)");
}

/**
 * @brief Advanced agent entry point.
 *
 * Accepts two optional command-line arguments:
 *   argv[1]  OTA server hostname (overrides CONFIG_EL2GO_OTA_SERVER_HOST)
 *   argv[2]  OTA server port     (overrides CONFIG_EL2GO_OTA_SERVER_PORT)
 * If not provided, the Kconfig compile-time values are used as defaults.
 * This allows runtime configuration on Linux and via CONFIG_BOOTARGS on Zephyr.
 *
 * Initializes the platform subsystems and the OTA context, reconciles the FWUAL
 * state against persisted agent state (confirming, rolling back, or reporting
 * as appropriate), and enters the scheduler loop on the main thread. On success
 * this function does not return.
 *
 * @return 1 if any initialization step fails (does not return on success)
 */
int main(int argc, char *argv[])
{
    static updater_ctx_t updater = { 0 };

    /* hostname and port default to compile-time Kconfig values.
     * On Linux (or Zephyr with CONFIG_BOOTARGS) they can be overridden
     * at runtime: <hostname> [port] */
    const char *hostname = CONFIG_EL2GO_OTA_SERVER_HOST;
    int port = CONFIG_EL2GO_OTA_SERVER_PORT;

    if (argc > 1) {
        hostname = argv[1];
    }
    if (argc > 2) {
        port = atoi(argv[2]);
        if (port < 0 || port > 65535) {
            OTA_DIAG_ERROR("invalid port value: %d", port);
            return 1;
        }
    }

    static const uint8_t server_ca_chain[] = { EL2GO_OTA_TRUSTED_ROOT_CA_CERT };

    const el2go_ota_mtls_config_t config = {
        .hostname = hostname,
        .port = (uint16_t)port,
        .server_ca_chain = server_ca_chain,
        .server_ca_chain_size = sizeof(server_ca_chain),
        .client_key_object_id = CONFIG_EL2GO_OTA_CLIENT_KEY_OBJECT_ID,
        .client_cert_object_id = CONFIG_EL2GO_OTA_CLIENT_CERT_OBJECT_ID,
    };

    /* Replay the previous session's diagnostics log, if the backend records one. */
    el2go_ota_diag_boot_replay();

    OTA_DIAG_INFO("==== OTA AGENT ADVANCED SAMPLE ====");
    OTA_DIAG_INFO("%s", OTA_FW_VERSION);

    fwual_result_t rc = fwual_init();
    if (rc != FWUAL_OK) {
        OTA_DIAG_FAIL("fwual_init()");
        OTA_DIAG_ERROR("err: %d", (int)rc);
        return 1;
    }
    OTA_DIAG_DONE("fwual_init()");

    fwual_state_t fw_state = fwual_get_state();
    OTA_DIAG_INFO("fwual state: %d", (int)fw_state);

    rc = fwual_get_caps(&updater.fwual_caps);
    if (rc != FWUAL_OK) {
        OTA_DIAG_FAIL("fwual_get_caps()");
        return 1;
    }
    OTA_DIAG_DONE("fwual_get_caps()");
    OTA_DIAG_INFO("caps: max_write=%u sequential=%d delta=%d", updater.fwual_caps.max_write_size,
                  (int)updater.fwual_caps.requires_sequential_writes,
                  (int)updater.fwual_caps.supports_delta);

    if (el2go_app_net_init() != 0) {
        OTA_DIAG_FAIL("el2go_app_net_init()");
        return 1;
    }
    OTA_DIAG_DONE("el2go_app_net_init()");

    el2go_app_time_sync();
    wait_for_time_sync();

    el2go_ota_status_t status = el2go_ota_init(&updater.ota_ctx, &config);
    if (status != EL2GO_OTA_SUCCESS) {
        OTA_DIAG_FAIL("el2go_ota_init()");
        OTA_DIAG_ERROR("%s", el2go_ota_get_error_string(status));
        return 1;
    }
    OTA_DIAG_DONE("el2go_ota_init()");

    status = el2go_ota_connect(updater.ota_ctx);
    if (status != EL2GO_OTA_SUCCESS) {
        OTA_DIAG_FAIL("el2go_ota_connect()");
        OTA_DIAG_ERROR("%s", el2go_ota_get_error_string(status));
        el2go_ota_cleanup(&updater.ota_ctx);
        return 1;
    }
    OTA_DIAG_DONE("el2go_ota_connect()");
    OTA_DIAG_INFO("connected to %s:%u", hostname, (unsigned)port);

    /* Reconcile persisted agent state against the current FWUAL state. */
    updater_finalize_boot(&updater, fw_state);

    OTA_DIAG_INFO("starting scheduler (base interval: %d s)", CONFIG_EL2GO_OTA_ADV_POLL_INTERVAL_S);
    scheduler_configure(on_scheduler_fire, &updater);
    scheduler_run_forever();

    return 0;
}
