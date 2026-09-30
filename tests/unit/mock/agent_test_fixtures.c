/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "agent_test_fixtures.h"

#include <string.h>
#include <stdio.h>

#include <psa/crypto.h>

#include "el2go_ota_lib_mock.h"

void agent_fixture_sha256_hex(const uint8_t *payload, size_t len, char *out)
{
    uint8_t digest[32] = { 0 };
    size_t hash_len = 0U;

    (void)psa_crypto_init();
    (void)psa_hash_compute(PSA_ALG_SHA_256, payload, len, digest, sizeof(digest), &hash_len);

    for (size_t i = 0; i < sizeof(digest); i++) {
        (void)snprintf(&out[i * 2], 3, "%02x", digest[i]);
    }
}

void agent_fixture_make_update_info(el2go_ota_update_info_t *update, const uint8_t *payload,
                                    size_t len)
{
    memset(update, 0, sizeof(*update));
    (void)strncpy(update->update_id, "update-1", sizeof(update->update_id) - 1U);
    update->package_count = 1U;

    el2go_ota_package_info_t *pkg = &update->packages[0];
    (void)strncpy(pkg->package_id, "package-1", sizeof(pkg->package_id) - 1U);
    pkg->file_count = 1U;

    el2go_ota_file_metadata_t *file = &pkg->files[0];
    (void)strncpy(file->file_id, "file-1", sizeof(file->file_id) - 1U);
    file->size = (int64_t)len;
    file->checksum_algorithm = EL2GO_OTA_CHECKSUM_ALG_SHA256;
    agent_fixture_sha256_hex(payload, len, file->checksum);
}

void agent_fixture_queue_update_available(const el2go_ota_update_info_t *update)
{
    el2go_ota_check_update_resp_t resp = { 0 };

    resp.update_available = true;
    resp.update_count = 1U;
    resp.updates[0] = *update;
    resp.first_update_id = resp.updates[0].update_id;
    resp.first_package_id = resp.updates[0].packages[0].package_id;

    el2go_ota_lib_mock_queue_check_response(&resp, EL2GO_OTA_SUCCESS);
}

void agent_fixture_queue_no_update(void)
{
    el2go_ota_check_update_resp_t resp = { 0 };

    resp.update_available = false;
    el2go_ota_lib_mock_queue_check_response(&resp, EL2GO_OTA_SUCCESS);
}
