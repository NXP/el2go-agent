/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

/*
 * Core OTA flow for the advanced agent.
 *
 * Implements the check, download, and handoff sequence: query the server for
 * updates, evaluate them against the local policy, stream each package into
 * FWUAL, commit and activate the new firmware, and reboot to apply it. On the
 * following boot, reconcile the FWUAL state and deliver the persisted status
 * report to the server.
 */

#include "updater.h"
#include "policy.h"
#include "scheduler.h"
#include "el2go_ota_diag.h"
#include "el2go_ota_persist.h"
#include "el2go_app_sys.h"

#include <stdio.h>
#include <string.h>

static const el2go_ota_attr_t device_attrs[] = {
    { "target_hw", "RW612" },
    { "fw_version", OTA_FW_VERSION },
};

#define DEVICE_ATTR_COUNT (sizeof(device_attrs) / sizeof(device_attrs[0]))

/* Length in hex characters of a SHA-256 checksum string (32 bytes * 2). */
#define EL2GO_OTA_SHA256_HEX_LEN 64U

/* Cap the backoff so large retry counts cannot overflow */
#define EL2GO_OTA_ADV_RETRY_MAX_EXPONENT 8U         /* 256x initial backoff */
#define EL2GO_OTA_ADV_RETRY_MAX_BACKOFF_MS 3600000U /* 1 hour ceiling */

/**
 * @brief Sleep for an exponential backoff interval before a retry.
 *
 * The delay is initial_backoff * 2^attempt, with the exponent clamped and the
 * result capped so it cannot overflow or grow without bound. The first attempt
 * (attempt <= 0) does not sleep.
 *
 * @param[in] attempt       Zero-based index; delay grows with it
 * @param[in] max_attempts  Total attempt count, only for logging
 * @param[in] what          label for the operation being retried
 */
static void retry_backoff(int attempt, int max_attempts, const char *what)
{
    unsigned int exponent = 0U;
    uint32_t backoff_ms = 0U;

    if (attempt <= 0) {
        return;
    }

    exponent = (unsigned int)attempt;
    if (exponent > EL2GO_OTA_ADV_RETRY_MAX_EXPONENT) {
        exponent = EL2GO_OTA_ADV_RETRY_MAX_EXPONENT;
    }

    backoff_ms =
        (uint32_t)CONFIG_EL2GO_OTA_ADV_RETRY_INITIAL_BACKOFF_S * 1000U * ((uint32_t)1U << exponent);

    if (backoff_ms > EL2GO_OTA_ADV_RETRY_MAX_BACKOFF_MS) {
        backoff_ms = EL2GO_OTA_ADV_RETRY_MAX_BACKOFF_MS;
    }

    OTA_DIAG_WARN("%s retry %d/%d in %u s", what, attempt + 1, max_attempts, backoff_ms / 1000U);
    el2go_app_sys_sleep_ms(backoff_ms);
}

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
 * FWUAL enforces sequential writes, so the running bytes_written count
 * is used as the write offset rather than the server provided offset. The count
 * is advanced only after a successful write so a failed attempt can resume from
 * exactly the bytes FWUAL has already accepted.
 *
 * @param[in] data    Chunk payload.
 * @param[in] len     Chunk length in bytes.
 * @param[in] offset  Server-reported offset (unused; see above).
 * @param[in] cb_ctx  Pointer to the chunk_cb_ctx_t for this download.
 *
 * @retval EL2GO_OTA_SUCCESS if the chunk was written
 * @retval EL2GO_OTA_ERROR_INTERNAL if the chunk is too large or the write failed
 */
static el2go_ota_status_t chunk_cb(const uint8_t *data, size_t len, size_t offset, void *cb_ctx)
{
    chunk_cb_ctx_t *ctx = (chunk_cb_ctx_t *)cb_ctx;

    (void)offset; /* Server offset is ignored; FWUAL requires sequential writes. */

    if (ctx->max_write_size > 0U && len > (size_t)ctx->max_write_size) {
        OTA_DIAG_ERROR("chunk size %zu exceeds max_write_size %u", len, ctx->max_write_size);
        ctx->last_fw_err = FWUAL_ERR_INVALID_PARAM;
        return EL2GO_OTA_ERROR_INTERNAL;
    }

    fwual_result_t rc =
        fwual_write(ctx->session, ctx->image_id, (uint64_t)ctx->bytes_written, data, len);
    if (rc != FWUAL_OK) {
        OTA_DIAG_FAIL("fwual_write()");
        OTA_DIAG_ERROR("offset=%zu err=%d", ctx->bytes_written, (int)rc);
        ctx->last_fw_err = rc;
        return EL2GO_OTA_ERROR_INTERNAL;
    }

    ctx->bytes_written += len;

    return EL2GO_OTA_SUCCESS;
}

/**
 * @brief Download all packages of an update and hand the images to FWUAL.
 *
 * Opens a FWUAL session, then for each package parses the expected SHA-256,
 * prepares and space-checks the image, downloads it (with in session resume and
 * retry), then finalizes and verifies it. After all packages succeed the
 * session is committed and activated. The pending-apply marker recorded in
 * @p persist survives a reboot so updater_finalize_boot() can report the
 * correct outcome.
 *
 * @param[in]     updater  Updater context (OTA handle and FWUAL capabilities)
 * @param[in]     update   Update descriptor listing the packages to apply
 * @param[in,out] persist  Persisted agent state, or NULL to skip persistence
 *
 * @retval EL2GO_OTA_SUCCESS if all packages were applied and activated
 * @retval EL2GO_OTA_ERROR_INTERNAL on any download, FWUAL, or session error
 */
static el2go_ota_status_t run_download_and_handoff(updater_ctx_t *updater,
                                                   const el2go_ota_update_info_t *update,
                                                   agent_persist_t *persist)
{
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

        OTA_DIAG_INFO("package[%zu]: id=%s files=%zu", i, pkg->package_id, pkg->file_count);

        if (pkg->file_count == 0U) {
            OTA_DIAG_WARN("empty package, skipping");
            continue;
        }

        file = &pkg->files[0];

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
        for (size_t j = 0; j < 32U; j++) {
            if (sscanf(&file->checksum[j * 2U], "%2x", &byte) != 1) {
                OTA_DIAG_ERROR("invalid checksum hex at pos %zu", j);
                status = EL2GO_OTA_ERROR_INTERNAL;
                goto cleanup;
            }
            expected_hash[j] = (uint8_t)byte;
        }

        const fwual_image_desc_t desc = {
            .image_id = image_id,
            .size = (uint64_t)file->size,
            .version = 0U,
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
        if (rc == FWUAL_ERR_NO_SPACE) {
            OTA_DIAG_FAIL("fwual_check_storage() - insufficient storage");
            status = EL2GO_OTA_ERROR_INTERNAL;
            goto cleanup;
        }
        OTA_DIAG_DONE("fwual_check_storage()");

        /*
         * Record the package being applied once, before download starts.
         * This survives a reboot so updater_finalize_boot() can report the
         * correct outcome (FAILURE/ROLLBACK). Written once per package.
         * It carries no download offset.
         */
        if (persist != NULL) {
            persist->state = (uint32_t)AGENT_STATE_DOWNLOAD;

            (void)strncpy(persist->update_id, update->update_id, sizeof(persist->update_id) - 1U);
            persist->update_id[sizeof(persist->update_id) - 1U] = '\0';

            (void)strncpy(persist->package_id, pkg->package_id, sizeof(persist->package_id) - 1U);
            persist->package_id[sizeof(persist->package_id) - 1U] = '\0';

            if (sizeof(persist->expected_version) != sizeof(pkg->version)) {
                OTA_DIAG_WARN("expected_version/version size mismatch (%zu vs %zu)",
                              sizeof(persist->expected_version), sizeof(pkg->version));
            }

            (void)strncpy(persist->expected_version, pkg->version,
                          sizeof(persist->expected_version) - 1U);
            persist->expected_version[sizeof(persist->expected_version) - 1U] = '\0';

            persist->valid = EL2GO_OTA_PERSIST_VALID_MAGIC;
            (void)el2go_ota_persist_write(persist);
        }

        /*
         * In-session resume only, not across reboots. On a failed attempt we
         * remember how many bytes FWUAL already accepted (bytes_written) and
         * ask the server to continue from there on the next attempt.
         */
        size_t resume_offset = 0U;

        OTA_DIAG_INFO("downloading image %u (%lld bytes)", (unsigned)image_id,
                      (long long)file->size);

        status = EL2GO_OTA_ERROR_INTERNAL;
        for (int attempt = 0; attempt < CONFIG_EL2GO_OTA_ADV_DOWNLOAD_MAX_RETRIES; attempt++) {
            retry_backoff(attempt, CONFIG_EL2GO_OTA_ADV_DOWNLOAD_MAX_RETRIES, "download");

            chunk_cb_ctx_t cb_ctx = {
                .session = session,
                .image_id = image_id,
                .last_fw_err = FWUAL_OK,
                .bytes_written = resume_offset,
                .max_write_size = updater->fwual_caps.max_write_size,
            };

            status = el2go_ota_download_package(updater->ota_ctx, update->update_id,
                                                pkg->package_id, file->file_id, resume_offset,
                                                chunk_cb, &cb_ctx);

            if (status == EL2GO_OTA_SUCCESS) {
                break;
            }

            OTA_DIAG_ERROR("download attempt %d failed: %s (fwual: %d)", attempt + 1,
                           el2go_ota_get_error_string(status), (int)cb_ctx.last_fw_err);

            /* Resume the next attempt from the bytes FWUAL already accepted (aligned). */
            resume_offset = cb_ctx.bytes_written;
        }

        if (status != EL2GO_OTA_SUCCESS) {
            OTA_DIAG_FAIL("el2go_ota_download_package() - all retries exhausted");

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
        status = EL2GO_OTA_ERROR_INTERNAL;
        /* Session already committed; close it directly instead of with cleanup. */
        fwual_close_session(session);
        return status;
    }
    OTA_DIAG_DONE("fwual_activate()");

    fwual_close_session(session);
    session = NULL;
    OTA_DIAG_DONE("fwual_close_session()");

    OTA_DIAG_INFO("download and handoff complete");
    return EL2GO_OTA_SUCCESS;

cleanup:
    if (session != NULL) {
        (void)fwual_close_session(session);
    }
    return status;
}

/**
 * @brief Report an update outcome to the server, retrying with backoff.
 *
 * @param[in] updater     Updater context holding the OTA handle.
 * @param[in] update_id   Update identifier being reported.
 * @param[in] package_id  Package identifier being reported.
 * @param[in] outcome     Outcome to report (success, failure, etc.).
 */
static void report_status_with_retry(updater_ctx_t *updater, const char *update_id,
                                     const char *package_id, el2go_ota_update_outcome_t outcome)
{
    el2go_ota_status_t status = EL2GO_OTA_ERROR_INTERNAL;

    for (int attempt = 0; attempt < CONFIG_EL2GO_OTA_ADV_REPORT_MAX_RETRIES; attempt++) {
        retry_backoff(attempt, CONFIG_EL2GO_OTA_ADV_REPORT_MAX_RETRIES, "status report");

        status = el2go_ota_report_status(updater->ota_ctx, update_id, package_id, outcome);
        if (status == EL2GO_OTA_SUCCESS) {
            break;
        }

        OTA_DIAG_ERROR("status report attempt %d failed: %s", attempt + 1,
                       el2go_ota_get_error_string(status));
    }

    if (status == EL2GO_OTA_SUCCESS) {
        OTA_DIAG_DONE("el2go_ota_report_status()");
    } else {
        OTA_DIAG_FAIL("el2go_ota_report_status() - all retries exhausted");
    }
}

/**
 * @brief Deliver status report that was persisted before the last reboot.
 *
 * @param[in] updater  Updater context holding the OTA handle.
 */
static void deliver_pending_status(updater_ctx_t *updater)
{
    el2go_ota_status_t status = EL2GO_OTA_ERROR_INTERNAL;

    for (int attempt = 0; attempt < CONFIG_EL2GO_OTA_ADV_REPORT_MAX_RETRIES; attempt++) {
        retry_backoff(attempt, CONFIG_EL2GO_OTA_ADV_REPORT_MAX_RETRIES, "status report");

        status = el2go_ota_report_pending_status(updater->ota_ctx);
        if (status == EL2GO_OTA_SUCCESS) {
            break;
        }

        OTA_DIAG_ERROR("status report attempt %d failed: %s", attempt + 1,
                       el2go_ota_get_error_string(status));
    }

    if (status == EL2GO_OTA_SUCCESS) {
        OTA_DIAG_DONE("el2go_ota_report_pending_status()");
    } else {
        OTA_DIAG_FAIL("el2go_ota_report_pending_status()");
    }
}

/**
 * @brief Rewrite the pending status entry as ROLLBACK, then deliver it.
 *
 * When FWUAL reports a rollback, the persisted SUCCESS entry recorded before
 * the reboot is overridden with a ROLLBACK outcome before being sent.
 *
 * @param[in] updater  Updater context holding the OTA handle.
 */
static void report_rollback(updater_ctx_t *updater)
{
    el2go_ota_pending_status_t pending = { 0 };

    el2go_ota_status_t status = el2go_ota_get_pending_status(&pending);
    if (status == EL2GO_OTA_SUCCESS && pending.valid == EL2GO_OTA_STATUS_VALID_MAGIC) {
        /* Override the persisted SUCCESS with ROLLBACK. */
        status = el2go_ota_schedule_status_report(pending.update_id, pending.package_id,
                                                  EL2GO_OTA_OUTCOME_ROLLBACK);
        if (status != EL2GO_OTA_SUCCESS) {
            OTA_DIAG_FAIL("el2go_ota_schedule_status_report(ROLLBACK)");
            OTA_DIAG_ERROR("%s", el2go_ota_get_error_string(status));
        }
    } else {
        OTA_DIAG_WARN("no pending status to override with ROLLBACK");
    }

    deliver_pending_status(updater);
}

void updater_finalize_boot(updater_ctx_t *updater, fwual_state_t fw_state)
{
    agent_persist_t persist = { 0 };
    (void)el2go_ota_persist_read(&persist);

    switch (fw_state) {
    case FWUAL_STATE_WAITING_CONFIRM:
        if (persist.valid == EL2GO_OTA_PERSIST_VALID_MAGIC && persist.expected_version[0] != '\0' &&
            strcmp(OTA_FW_VERSION, persist.expected_version) != 0) {
            OTA_DIAG_WARN("running %s but expected %s -- MCUBoot rejected swap", OTA_FW_VERSION,
                          persist.expected_version);
            (void)fwual_rollback();
            OTA_DIAG_WARN("rollback detected - reporting ROLLBACK to server");
            report_rollback(updater);
            (void)el2go_ota_persist_clear();
            break;
        }

        OTA_DIAG_INFO("new firmware validated - confirming image");

        if (fwual_confirm() != FWUAL_OK) {
            OTA_DIAG_FAIL("fwual_confirm()");
            /* An unconfirmed image reverts on the next reset. */
        } else {
            OTA_DIAG_DONE("fwual_confirm()");
        }

        deliver_pending_status(updater);
        (void)el2go_ota_persist_clear();
        break;

    case FWUAL_STATE_ROLLED_BACK:
        OTA_DIAG_WARN("rollback detected - reporting ROLLBACK to server");
        report_rollback(updater);
        (void)el2go_ota_persist_clear();
        break;

    case FWUAL_STATE_FAILED:
        OTA_DIAG_WARN("fwual reports FAILED - reporting failure and clearing state");
        if (persist.valid == EL2GO_OTA_PERSIST_VALID_MAGIC && persist.update_id[0] != '\0') {
            report_status_with_retry(updater, persist.update_id, persist.package_id,
                                     EL2GO_OTA_OUTCOME_FAILURE);
        }
        (void)el2go_ota_persist_clear();
        break;

    case FWUAL_STATE_WRITING:
    case FWUAL_STATE_STAGED:
    case FWUAL_STATE_COMMITTED:
        OTA_DIAG_WARN("interrupted update session (fwual state %d) - will retry on next check",
                      (int)fw_state);
        break;

    case FWUAL_STATE_IDLE:
    case FWUAL_STATE_ACTIVE:
    default:
        if (persist.valid == EL2GO_OTA_PERSIST_VALID_MAGIC) {
            (void)el2go_ota_persist_clear();
        }
        break;
    }
}

void updater_run_check(updater_ctx_t *updater)
{
    agent_persist_t persist = { 0 };
    el2go_ota_check_update_resp_t resp = { 0 };
    const el2go_ota_update_info_t *update = NULL;
    const char *update_id = NULL;
    const char *package_id = NULL;
    uint32_t remaining_ms = 0U;

    if (!el2go_ota_is_connected(updater->ota_ctx)) {
        OTA_DIAG_WARN("connection lost - reconnecting");
        el2go_ota_disconnect(updater->ota_ctx);

        el2go_ota_status_t connect_rc = el2go_ota_connect(updater->ota_ctx);
        if (connect_rc != EL2GO_OTA_SUCCESS) {
            OTA_DIAG_FAIL("el2go_ota_connect()");
            OTA_DIAG_ERROR("%s", el2go_ota_get_error_string(connect_rc));
            scheduler_backoff();
            return;
        }
        OTA_DIAG_DONE("el2go_ota_connect()");
    }

    OTA_DIAG_INFO("checking for updates...");

    el2go_ota_status_t status =
        el2go_ota_check_for_updates(updater->ota_ctx, device_attrs, DEVICE_ATTR_COUNT, &resp);
    if (status != EL2GO_OTA_SUCCESS) {
        OTA_DIAG_FAIL("el2go_ota_check_for_updates()");
        OTA_DIAG_ERROR("%s", el2go_ota_get_error_string(status));
        scheduler_backoff();
        return;
    }
    OTA_DIAG_DONE("el2go_ota_check_for_updates()");

    policy_result_t policy = policy_evaluate(&resp);

    switch (policy) {
    case POLICY_CANCEL:
        OTA_DIAG_INFO("no update available - staying idle");
        scheduler_reset();
        return;

    case POLICY_BLACKOUT:
        scheduler_rearm_ms(3600U * 1000U);
        return;

    case POLICY_DEFER:
        remaining_ms = policy_defer_remaining_ms();
        scheduler_rearm_ms(remaining_ms > 0U ? remaining_ms : 60U * 1000U);
        return;

    case POLICY_PROCEED:
    default:
        break;
    }

    OTA_DIAG_INFO("update available: id=%s packages=%zu",
                  resp.first_update_id ? resp.first_update_id : "?", resp.updates[0].package_count);

    policy_record_attempt();

    update = &resp.updates[0];
    update_id = update->update_id;
    package_id = (update->package_count > 0U) ? update->packages[0].package_id : update_id;

    /* Load any persisted state before starting the download. */
    (void)el2go_ota_persist_read(&persist);

    status = run_download_and_handoff(updater, update, &persist);
    if (status != EL2GO_OTA_SUCCESS) {
        OTA_DIAG_ERROR("download/handoff failed: %s", el2go_ota_get_error_string(status));
        report_status_with_retry(updater, update_id, package_id, EL2GO_OTA_OUTCOME_FAILURE);
        /* Clear the slot on failure so the next attempt starts clean. */
        (void)el2go_ota_persist_clear();
        scheduler_backoff();
        return;
    }

    /* Handoff done; mark the reboot state so the next boot can finalize. */
    persist.state = (uint32_t)AGENT_STATE_REBOOT;
    persist.valid = EL2GO_OTA_PERSIST_VALID_MAGIC;
    (void)el2go_ota_persist_write(&persist);

    /* Persist the status report so it survives the reboot. */
    status = el2go_ota_schedule_status_report(update_id, package_id, EL2GO_OTA_OUTCOME_SUCCESS);
    if (status != EL2GO_OTA_SUCCESS) {
        OTA_DIAG_FAIL("el2go_ota_schedule_status_report()");
        OTA_DIAG_ERROR("%s", el2go_ota_get_error_string(status));
    } else {
        OTA_DIAG_DONE("el2go_ota_schedule_status_report()");
    }

    OTA_DIAG_INFO("activating update...");
    el2go_ota_disconnect(updater->ota_ctx);
    el2go_ota_cleanup(&updater->ota_ctx);
    if (el2go_app_sys_activate_update() != 0) {
        OTA_DIAG_ERROR("activation failed");
    }

    /* On Zephyr this line is never reached. */
}
