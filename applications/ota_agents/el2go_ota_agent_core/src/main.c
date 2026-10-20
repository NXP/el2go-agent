/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

/*
 * Core OTA agent sample.
 *
 * A minimal single-threaded agent: poll the EL2GO OTA server for updates,
 * download any available package over mTLS, hand the image to FWUAL, and reboot
 * to apply it. All agent logic runs on the main thread; no worker thread is
 * created. It demonstrates the essential update flow without the scheduler,
 * policy, retry, or persistence features of the advanced sample.
 */

#include "fwual/fwual.h"
#include "ota/el2go_ota_lib.h"
#include "ota/el2go_ota_certificates.h"

#include "el2go_app_net.h"
#include "el2go_app_sys.h"

#include "el2go_ota_diag.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* The Interval is configured in seconds; converted to milliseconds for el2go_app_sys_sleep_ms(). */
#define EL2GO_OTA_POLL_INTERVAL_MS ((uint32_t)CONFIG_EL2GO_OTA_POLL_INTERVAL_S * 1000U)

static const el2go_ota_attr_t device_attrs[] = {
    { "target_hw", "RW612" },
    { "fw_version", OTA_FW_VERSION },
};

#define DEVICE_ATTR_COUNT (sizeof(device_attrs) / sizeof(device_attrs[0]))

/* Length in hex characters of a SHA-256 checksum string (32 bytes * 2). */
#define EL2GO_OTA_SHA256_HEX_LEN 64U

/** @brief Updater context for the core agent's poll loop. */
typedef struct {
    el2go_ota_ctx_t *ota_ctx;
    fwual_caps_t fwual_caps;
    uint32_t connect_fail_count; /* throttles reconnect-failure log spam */
} core_updater_ctx_t;

/** @brief Context passed to chunk_cb() while streaming a package into FWUAL. */
typedef struct {
    fwual_session_t *session;
    fwual_image_id_t image_id;
    fwual_result_t last_fw_err;
    size_t bytes_written;
    uint32_t max_write_size;
} chunk_cb_ctx_t;

/**
 * @brief Download callback that writes each received chunk into FWUAL.
 *
 * FWUAL requires sequential writes, so the running bytes_written count
 * is used as the write offset and the server provided offset is ignored.
 *
 * @param[in] data    Chunk payload
 * @param[in] len     Chunk length in bytes
 * @param[in] offset  Server-reported offset (unused; see above)
 * @param[in] cb_ctx  Pointer to the chunk_cb_ctx_t for this download
 *
 * @retval EL2GO_OTA_SUCCESS if the chunk was written
 * @retval EL2GO_OTA_ERROR_INTERNAL if the chunk is too large or the write failed
 */
static el2go_ota_status_t chunk_cb(const uint8_t *data, size_t len, size_t offset, void *cb_ctx)
{
    chunk_cb_ctx_t *ctx = (chunk_cb_ctx_t *)cb_ctx;

    (void)offset;

    if (ctx->max_write_size > 0 && len > (size_t)ctx->max_write_size) {
        OTA_DIAG_ERROR("chunk size %zu exceeds max_write_size %u", len, ctx->max_write_size);
        ctx->last_fw_err = FWUAL_ERR_INVALID_PARAM;
        return EL2GO_OTA_ERROR_INTERNAL;
    }

    fwual_result_t fw_status =
        fwual_write(ctx->session, ctx->image_id, (uint64_t)ctx->bytes_written, data, len);
    if (fw_status != FWUAL_OK) {
        OTA_DIAG_FAIL("fwual_write()");
        OTA_DIAG_ERROR("offset: %zu, err: %d", ctx->bytes_written, (int)fw_status);
        ctx->last_fw_err = fw_status;
        return EL2GO_OTA_ERROR_INTERNAL;
    }

    ctx->bytes_written += len;
    return EL2GO_OTA_SUCCESS;
}

/**
 * @brief Download all packages of an update and hand the images to FWUAL.
 *
 * Opens a FWUAL session, then for each package parses the expected SHA-256,
 * prepares and space checks the image, downloads it, then finalizes and
 * verifies it. After all packages succeed the session is committed and
 * activated. The commit before activate and close after activate ordering is
 * intentional: once the session is committed, activation failure still requires
 * the session to be closed rather than routed through the error cleanup path.
 *
 * @param[in] ctx     OTA context
 * @param[in] update  Update descriptor listing the packages to apply
 *
 * @retval EL2GO_OTA_SUCCESS if all packages were applied and activated
 * @retval EL2GO_OTA_ERROR_INTERNAL on any download, FWUAL, or session error
 */
static el2go_ota_status_t run_download_and_handoff(core_updater_ctx_t *updater,
                                                   const el2go_ota_update_info_t *update)
{
    el2go_ota_ctx_t *ctx = updater->ota_ctx;
    fwual_session_t *session = NULL;

    const el2go_ota_file_metadata_t *file = NULL;
    uint8_t expected_hash[32] = { 0 };
    size_t checksum_len = 0U;
    unsigned int byte = 0U;

    fwual_result_t rc = fwual_open_session(&session);
    if (rc != FWUAL_OK) {
        OTA_DIAG_FAIL("fwual_open_session()");
        return EL2GO_OTA_ERROR_INTERNAL;
    }
    OTA_DIAG_DONE("fwual_open_session()");

    el2go_ota_status_t status = EL2GO_OTA_ERROR_INTERNAL; /* safe default for goto cleanup */

    OTA_DIAG_INFO("packages to process: %zu", update->package_count);

    for (size_t i = 0; i < update->package_count; i++) {
        const el2go_ota_package_info_t *pkg = &update->packages[i];
        fwual_image_id_t image_id = (fwual_image_id_t)i;

        OTA_DIAG_INFO("package[%zu]: id=%s, files=%zu", i, pkg->package_id, pkg->file_count);

        if (pkg->file_count == 0) {
            OTA_DIAG_WARN("empty package, skipping");
            continue;
        }

        file = &pkg->files[0];

        /* Parse the hex encoded SHA-256 from the file metadata */
        if (file->checksum_algorithm != EL2GO_OTA_CHECKSUM_ALG_SHA256 &&
            file->checksum_algorithm != EL2GO_OTA_CHECKSUM_ALG_UNSPECIFIED) {
            OTA_DIAG_ERROR("unsupported checksum algorithm: %d", (int)file->checksum_algorithm);
            status = EL2GO_OTA_ERROR_INTERNAL;
            goto cleanup;
        }
        checksum_len = strlen(file->checksum);
        if (checksum_len < EL2GO_OTA_SHA256_HEX_LEN) {
            OTA_DIAG_ERROR("checksum too short: %zu", checksum_len);
            status = EL2GO_OTA_ERROR_INTERNAL;
            goto cleanup;
        }
        for (size_t j = 0; j < 32; j++) {
            if (sscanf(&file->checksum[j * 2], "%2x", &byte) != 1) {
                OTA_DIAG_ERROR("invalid checksum hex at pos %zu", j);
                status = EL2GO_OTA_ERROR_INTERNAL;
                goto cleanup;
            }
            expected_hash[j] = (uint8_t)byte;
        }

        const fwual_image_desc_t desc = {
            .image_id = image_id,
            .size = (uint64_t)file->size,
            .version = 0,
            .update_type = FWUAL_UPDATE_FULL,
            .hash_algo = "sha256",
            .expected_hash = expected_hash,
            .hash_len = sizeof(expected_hash),
        };

        rc = fwual_prepare_image(session, &desc);
        if (rc != FWUAL_OK) {
            OTA_DIAG_FAIL("fwual_prepare_image()");
            status = EL2GO_OTA_ERROR_INTERNAL;
            goto cleanup;
        }
        OTA_DIAG_DONE("fwual_prepare_image()");

        rc = fwual_check_storage(session, image_id);
        if (rc != FWUAL_OK) {
            OTA_DIAG_FAIL("fwual_check_storage()");
            if (rc == FWUAL_ERR_NO_SPACE)
                OTA_DIAG_ERROR("insufficient storage for image %u", (unsigned)image_id);
            else
                OTA_DIAG_ERROR("fwual_check_storage: %d", (int)rc);
            status = EL2GO_OTA_ERROR_INTERNAL;
            goto cleanup;
        }
        OTA_DIAG_DONE("fwual_check_storage()");

        chunk_cb_ctx_t cb_ctx = {
            .session = session,
            .image_id = image_id,
            .last_fw_err = FWUAL_OK,
            .bytes_written = 0,
            .max_write_size = updater->fwual_caps.max_write_size,
        };

        OTA_DIAG_INFO("downloading image %u, size %lld bytes", (unsigned)image_id,
                      (long long)file->size);

        status = el2go_ota_download_package(ctx, update->update_id, pkg->package_id, file->file_id,
                                            0, chunk_cb, &cb_ctx);
        if (status != EL2GO_OTA_SUCCESS) {
            OTA_DIAG_FAIL("el2go_ota_download_package()");
            OTA_DIAG_ERROR("%s (fwual: %d)", el2go_ota_get_error_string(status),
                           (int)cb_ctx.last_fw_err);
            goto cleanup;
        }
        OTA_DIAG_DONE("el2go_ota_download_package()");

        rc = fwual_finalize_image(session, image_id);
        if (rc != FWUAL_OK) {
            OTA_DIAG_FAIL("fwual_finalize_image()");
            status = EL2GO_OTA_ERROR_INTERNAL;
            goto cleanup;
        }
        OTA_DIAG_DONE("fwual_finalize_image()");

        rc = fwual_verify_image(session, image_id);
        if (rc != FWUAL_OK) {
            OTA_DIAG_FAIL("fwual_verify_image()");
            status = EL2GO_OTA_ERROR_INTERNAL;
            goto cleanup;
        }
        OTA_DIAG_DONE("fwual_verify_image()");
    }

    rc = fwual_commit_session(session);
    if (rc != FWUAL_OK) {
        OTA_DIAG_FAIL("fwual_commit_session()");
        status = EL2GO_OTA_ERROR_INTERNAL;
        goto cleanup;
    }
    OTA_DIAG_DONE("fwual_commit_session()");

    rc = fwual_activate();
    if (rc != FWUAL_OK) {
        OTA_DIAG_FAIL("fwual_activate()");
        /* Session already committed; close it directly before returning */
        (void)fwual_close_session(session);
        return EL2GO_OTA_ERROR_INTERNAL;
    }
    OTA_DIAG_DONE("fwual_activate()");

    fwual_close_session(session);
    session = NULL;
    OTA_DIAG_DONE("fwual_close_session()");

    OTA_DIAG_INFO("Download and Handoff Complete");
    return EL2GO_OTA_SUCCESS;

cleanup:
    if (session != NULL) {
        (void)fwual_close_session(session);
    }
    return status;
}

/**
 * @brief Perform one update check and, if an update is available, apply it.
 *
 * Queries the server for updates. If one is available it is downloaded and
 * handed to FWUAL; on success a status report is scheduled and the device
 * reboots to apply the update (this function does not return in that case). On
 * failure the outcome is reported and the function returns.
 *
 * @param[in] ctx  OTA context
 */
static void core_updater_run_check(core_updater_ctx_t *updater)
{
    el2go_ota_check_update_resp_t resp = { 0 };
    const el2go_ota_update_info_t *update = NULL;
    const char *update_id = NULL;
    const char *package_id = NULL;

    if (!el2go_ota_is_connected(updater->ota_ctx)) {
        OTA_DIAG_WARN("connection lost - reconnecting");
        el2go_ota_disconnect(updater->ota_ctx);

        el2go_ota_status_t rc = el2go_ota_connect(updater->ota_ctx);
        if (rc != EL2GO_OTA_SUCCESS) {
            updater->connect_fail_count++;
            if (updater->connect_fail_count <= 3U) {
                OTA_DIAG_FAIL("el2go_ota_connect()");
                OTA_DIAG_ERROR("%s", el2go_ota_get_error_string(rc));
            }
            return;
        }
        OTA_DIAG_DONE("el2go_ota_connect()");
        updater->connect_fail_count = 0U;
    }

    OTA_DIAG_INFO("checking for updates...");

    el2go_ota_status_t status =
        el2go_ota_check_for_updates(updater->ota_ctx, device_attrs, DEVICE_ATTR_COUNT, &resp);
    if (status != EL2GO_OTA_SUCCESS) {
        OTA_DIAG_FAIL("el2go_ota_check_for_updates()");
        OTA_DIAG_ERROR("%s", el2go_ota_get_error_string(status));
        return;
    }
    OTA_DIAG_DONE("el2go_ota_check_for_updates()");

    if (!resp.update_available || resp.update_count == 0) {
        OTA_DIAG_INFO("No update available - staying idle");
        return;
    }

    OTA_DIAG_INFO("update available: id=%s, packages=%zu",
                  resp.first_update_id ? resp.first_update_id : "?", resp.updates[0].package_count);

    update = &resp.updates[0];
    update_id = update->update_id;
    package_id = (update->package_count > 0) ? update->packages[0].package_id : update_id;

    status = run_download_and_handoff(updater, update);
    if (status != EL2GO_OTA_SUCCESS) {
        OTA_DIAG_ERROR("download/handoff failed: %s", el2go_ota_get_error_string(status));
        el2go_ota_report_status(updater->ota_ctx, update_id, package_id, EL2GO_OTA_OUTCOME_FAILURE);
        return;
    }

    status = el2go_ota_schedule_status_report(update_id, package_id, EL2GO_OTA_OUTCOME_SUCCESS);
    if (status != EL2GO_OTA_SUCCESS) {
        OTA_DIAG_FAIL("el2go_ota_schedule_status_report()");
        OTA_DIAG_ERROR("err: %s", el2go_ota_get_error_string(status));
    } else {
        OTA_DIAG_DONE("el2go_ota_schedule_status_report()");
        OTA_DIAG_INFO("STATUS_SUCCESS scheduled");
    }

    OTA_DIAG_INFO("activating update...");
    el2go_ota_disconnect(updater->ota_ctx);
    el2go_ota_cleanup(&updater->ota_ctx);
    if (el2go_app_sys_activate_update() != 0) {
        OTA_DIAG_ERROR("activation failed");
    }

    /* On Zephyr this line is never reached. */
}

static void core_updater_finalize_boot(core_updater_ctx_t *updater, fwual_state_t fw_state)
{
    if (fw_state == FWUAL_STATE_WAITING_CONFIRM) {
        OTA_DIAG_INFO("new firmware validated - confirming image");
        if (fwual_confirm() != FWUAL_OK) {
            OTA_DIAG_FAIL("fwual_confirm()"); /* An unconfirmed image reverts on the next reset. */
        } else {
            OTA_DIAG_DONE("fwual_confirm()");
        }

        el2go_ota_status_t status = EL2GO_OTA_ERROR_INTERNAL;

        for (int report_attempt = 0; report_attempt < CONFIG_EL2GO_OTA_CORE_REPORT_MAX_RETRIES;
             report_attempt++) {
            if (report_attempt > 0) {
                el2go_app_sys_sleep_ms(EL2GO_OTA_POLL_INTERVAL_MS);
            }

            status = el2go_ota_report_pending_status(updater->ota_ctx);
            if (status == EL2GO_OTA_SUCCESS) {
                OTA_DIAG_DONE("el2go_ota_report_pending_status()");
                break;
            }

            OTA_DIAG_ERROR("status report attempt %d failed: %s", report_attempt + 1,
                           el2go_ota_get_error_string(status));
        }

        if (status != EL2GO_OTA_SUCCESS) {
            OTA_DIAG_FAIL("el2go_ota_report_pending_status()");
        }
    }
}

/**
 * @brief Core agent entry point.
 *
 * Accepts two optional command-line arguments:
 *   argv[1]  OTA server hostname (overrides CONFIG_EL2GO_OTA_SERVER_HOST)
 *   argv[2]  OTA server port     (overrides CONFIG_EL2GO_OTA_SERVER_PORT)
 * If not provided, the Kconfig compile-time values are used as defaults.
 * This allows runtime configuration on Linux and via CONFIG_BOOTARGS on Zephyr.
 *
 * Initializes FWUAL, networking, credentials, and the OTA context (which brings
 * up PSA crypto via el2go_platform_init), connects to the server, confirms a
 * freshly booted image if one is awaiting confirmation, then enters the poll
 * loop on the main thread. On success this function does not return.
 *
 * @return 1 if any initialization step fails (does not return on success)
 */
int main(int argc, char *argv[])
{
    core_updater_ctx_t updater = { 0 };

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

    OTA_DIAG_INFO("==== OTA AGENT CORE SAMPLE ====");
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
    OTA_DIAG_INFO("caps: max_write=%u, sequential=%d, delta=%d", updater.fwual_caps.max_write_size,
                  (int)updater.fwual_caps.requires_sequential_writes,
                  (int)updater.fwual_caps.supports_delta);

    if (el2go_app_net_init() != 0) {
        OTA_DIAG_FAIL("el2go_app_net_init()");
        return 1;
    }
    OTA_DIAG_DONE("el2go_app_net_init()");

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

    core_updater_finalize_boot(&updater, fw_state);

    OTA_DIAG_INFO("entering update-check loop (poll: %u ms)", EL2GO_OTA_POLL_INTERVAL_MS);

    /* Runs the poll loop on the main thread; does not return. */
    for (;;) {
        core_updater_run_check(&updater);
        el2go_app_sys_sleep_ms(EL2GO_OTA_POLL_INTERVAL_MS);
    }

    return 0;
}
