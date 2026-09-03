/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <string.h>
#include <psa/crypto.h>
#include "fwual/fwual.h"

#define FWUAL_MOCK_MAX_IMAGES 4U
#define FWUAL_MOCK_IMAGE_BUF_SIZE 4096U

typedef struct {
    fwual_image_id_t image_id;
    fwual_image_desc_t desc;
    bool prepared;
    bool cancelled;
    bool finalized;
    bool verified;
    bool committed;
    uint64_t bytes_written;
    uint64_t next_expected_offset;
    uint8_t data[FWUAL_MOCK_IMAGE_BUF_SIZE];
} fwual_mock_image_t;

struct fwual_session {
    bool active;
    size_t image_count;
    fwual_mock_image_t images[FWUAL_MOCK_MAX_IMAGES];
};

typedef struct {
    bool initialized;
    fwual_caps_t caps;
    fwual_state_t lifecycle_state;
    struct fwual_session session;
} fwual_mock_state_t;

static fwual_mock_state_t s_mock;

static fwual_mock_image_t *find_active_image(fwual_image_id_t image_id)
{
    size_t i = 0U;

    if (s_mock.session.images == NULL) {
        return NULL;
    }

    for (i = 0U; i < s_mock.session.image_count; i++) {
        fwual_mock_image_t *slot = &s_mock.session.images[i];

        if (slot != NULL && slot->image_id == image_id && slot->prepared && !slot->cancelled) {
            return slot;
        }
    }
    return NULL;
}

fwual_result_t fwual_init(void)
{
    if (s_mock.initialized) {
        return FWUAL_OK;
    }

    memset(&s_mock, 0, sizeof(s_mock));

    s_mock.caps.requires_sequential_writes = true;
    s_mock.caps.rejects_overlaps = true;
    s_mock.caps.supports_delta = false;
    s_mock.caps.write_alignment = 1U;
    s_mock.caps.max_write_size = 0U;

    s_mock.lifecycle_state = FWUAL_STATE_IDLE;
    s_mock.initialized = true;

    return FWUAL_OK;
}

fwual_result_t fwual_get_caps(fwual_caps_t *out_caps)
{
    if (out_caps == NULL) {
        return FWUAL_ERR_INVALID_PARAM;
    }
    if (!s_mock.initialized) {
        return FWUAL_ERR_INVALID_STATE;
    }

    *out_caps = s_mock.caps;
    return FWUAL_OK;
}

fwual_result_t fwual_open_session(fwual_session_t **out_session)
{
    if (out_session == NULL) {
        return FWUAL_ERR_INVALID_PARAM;
    }
    if (!s_mock.initialized) {
        return FWUAL_ERR_INVALID_STATE;
    }
    if (s_mock.session.active) {
        return FWUAL_ERR_BUSY;
    }

    memset(&s_mock.session, 0, sizeof(s_mock.session));
    s_mock.session.active = true;

    *out_session = &s_mock.session;
    return FWUAL_OK;
}

fwual_result_t fwual_close_session(fwual_session_t *session)
{
    if (session == NULL) {
        return FWUAL_OK;
    }
    if (session != &s_mock.session) {
        return FWUAL_ERR_INVALID_PARAM;
    }
    if (!s_mock.session.active) {
        return FWUAL_OK;
    }

    memset(&s_mock.session, 0, sizeof(s_mock.session));
    return FWUAL_OK;
}

fwual_result_t fwual_prepare_image(fwual_session_t *session, const fwual_image_desc_t *desc)
{
    size_t i = 0U;
    fwual_mock_image_t *slot = NULL;

    if (session == NULL || desc == NULL || session != &s_mock.session) {
        return FWUAL_ERR_INVALID_PARAM;
    }
    if (!s_mock.session.active) {
        return FWUAL_ERR_INVALID_STATE;
    }
    if (desc->size > FWUAL_MOCK_IMAGE_BUF_SIZE) {
        return FWUAL_ERR_NO_SPACE;
    }

    if (find_active_image(desc->image_id) != NULL) {
        return FWUAL_ERR_INVALID_PARAM;
    }

    for (i = 0U; i < s_mock.session.image_count; i++) {
        if (s_mock.session.images[i].cancelled) {
            slot = &s_mock.session.images[i];
            break;
        }
    }

    if (slot == NULL) {
        if (s_mock.session.image_count >= FWUAL_MOCK_MAX_IMAGES) {
            return FWUAL_ERR_NO_SPACE;
        }
        slot = &s_mock.session.images[s_mock.session.image_count];
        s_mock.session.image_count++;
    }

    memset(slot, 0, sizeof(*slot));
    slot->image_id = desc->image_id;
    slot->desc = *desc;
    slot->prepared = true;

    return FWUAL_OK;
}

fwual_result_t fwual_check_storage(fwual_session_t *session, fwual_image_id_t image_id)
{
    fwual_mock_image_t *slot = NULL;

    if (session == NULL || session != &s_mock.session) {
        return FWUAL_ERR_INVALID_PARAM;
    }
    if (!s_mock.session.active) {
        return FWUAL_ERR_INVALID_STATE;
    }

    slot = find_active_image(image_id);
    if (slot == NULL) {
        return FWUAL_ERR_INVALID_STATE;
    }

    return FWUAL_OK;
}

fwual_result_t fwual_cancel_image(fwual_session_t *session, fwual_image_id_t image_id)
{
    fwual_mock_image_t *slot = NULL;

    if (session == NULL || session != &s_mock.session) {
        return FWUAL_ERR_INVALID_PARAM;
    }
    if (!s_mock.session.active) {
        return FWUAL_ERR_INVALID_STATE;
    }

    slot = find_active_image(image_id);
    if (slot == NULL) {
        return FWUAL_ERR_INVALID_STATE;
    }

    slot->cancelled = true;
    slot->prepared = false;

    return FWUAL_OK;
}

fwual_result_t fwual_write(fwual_session_t *session, fwual_image_id_t image_id, uint64_t offset,
                           const uint8_t *data, size_t len)
{
    fwual_mock_image_t *slot = NULL;

    if (session == NULL || data == NULL || len == 0U || session != &s_mock.session) {
        return FWUAL_ERR_INVALID_PARAM;
    }
    if (!s_mock.session.active) {
        return FWUAL_ERR_INVALID_STATE;
    }

    slot = find_active_image(image_id);
    if (slot == NULL || slot->finalized) {
        return FWUAL_ERR_INVALID_STATE;
    }

    if (s_mock.caps.requires_sequential_writes && offset != slot->next_expected_offset) {
        return FWUAL_ERR_INVALID_STATE;
    }

    if (offset > slot->desc.size) {
        return FWUAL_ERR_INVALID_PARAM;
    }

    if (offset + (uint64_t)len > slot->desc.size) {
        return FWUAL_ERR_INVALID_PARAM;
    }

    memcpy(&slot->data[offset], data, len);
    slot->bytes_written += (uint64_t)len;
    slot->next_expected_offset = offset + (uint64_t)len;

    return FWUAL_OK;
}

fwual_result_t fwual_finalize_image(fwual_session_t *session, fwual_image_id_t image_id)
{
    fwual_mock_image_t *slot = NULL;

    if (session == NULL || session != &s_mock.session) {
        return FWUAL_ERR_INVALID_PARAM;
    }
    if (!s_mock.session.active) {
        return FWUAL_ERR_INVALID_STATE;
    }

    slot = find_active_image(image_id);
    if (slot == NULL || slot->finalized) {
        return FWUAL_ERR_INVALID_STATE;
    }

    if (slot->bytes_written < slot->desc.size) {
        return FWUAL_ERR_INVALID_STATE;
    }

    slot->finalized = true;
    return FWUAL_OK;
}

fwual_result_t fwual_verify_image(fwual_session_t *session, fwual_image_id_t image_id)
{
    fwual_mock_image_t *slot = NULL;
    uint8_t computed[32] = { 0 };
    size_t hash_len = 0U;
    psa_status_t ps = PSA_ERROR_GENERIC_ERROR;

    if (session == NULL || session != &s_mock.session) {
        return FWUAL_ERR_INVALID_PARAM;
    }
    if (!s_mock.session.active) {
        return FWUAL_ERR_INVALID_STATE;
    }

    slot = find_active_image(image_id);
    if (slot == NULL) {
        return FWUAL_ERR_INVALID_STATE;
    }

    if (!slot->finalized) {
        return FWUAL_ERR_INVALID_STATE;
    }

    if (slot->desc.expected_hash == NULL || slot->desc.hash_len == 0U) {
        return FWUAL_ERR_INVALID_PARAM;
    }

    if (slot->desc.hash_algo == NULL || strcmp(slot->desc.hash_algo, "sha256") != 0) {
        return FWUAL_ERR_UNSUPPORTED;
    }

    if (slot->desc.hash_len != 32U) {
        return FWUAL_ERR_INVALID_PARAM;
    }

    if (psa_crypto_init() != PSA_SUCCESS) {
        return FWUAL_ERR_INTERNAL;
    }

    ps = psa_hash_compute(PSA_ALG_SHA_256, slot->data, (size_t)slot->desc.size, computed,
                          sizeof(computed), &hash_len);
    if (ps != PSA_SUCCESS || hash_len != 32U) {
        return FWUAL_ERR_INTERNAL;
    }

    if (memcmp(computed, slot->desc.expected_hash, 32U) != 0) {
        return FWUAL_ERR_CORRUPT;
    }

    slot->verified = true;
    return FWUAL_OK;
}

fwual_result_t fwual_commit_session(fwual_session_t *session)
{
    size_t i = 0U;

    if (session == NULL || session != &s_mock.session) {
        return FWUAL_ERR_INVALID_PARAM;
    }
    if (!s_mock.session.active) {
        return FWUAL_ERR_INVALID_STATE;
    }

    for (i = 0U; i < s_mock.session.image_count; i++) {
        fwual_mock_image_t *slot = &s_mock.session.images[i];

        if (!slot->prepared || slot->cancelled) {
            continue;
        }
        if (slot->finalized && !slot->verified) {
            return FWUAL_ERR_INVALID_STATE;
        }
    }

    for (i = 0U; i < s_mock.session.image_count; i++) {
        fwual_mock_image_t *slot = &s_mock.session.images[i];

        if (slot->prepared && !slot->cancelled && slot->verified) {
            slot->committed = true;
        }
    }

    s_mock.lifecycle_state = FWUAL_STATE_COMMITTED;
    return FWUAL_OK;
}

fwual_result_t fwual_activate(void)
{
    if (!s_mock.initialized) {
        return FWUAL_ERR_INVALID_STATE;
    }
    if (s_mock.lifecycle_state != FWUAL_STATE_COMMITTED) {
        return FWUAL_ERR_INVALID_STATE;
    }

    s_mock.lifecycle_state = FWUAL_STATE_REBOOT_REQUIRED;
    return FWUAL_OK;
}

fwual_result_t fwual_confirm(void)
{
    if (!s_mock.initialized) {
        return FWUAL_ERR_INVALID_STATE;
    }
    if (s_mock.lifecycle_state != FWUAL_STATE_WAITING_CONFIRM) {
        return FWUAL_ERR_INVALID_STATE;
    }

    s_mock.lifecycle_state = FWUAL_STATE_ACTIVE;
    return FWUAL_OK;
}

fwual_result_t fwual_rollback(void)
{
    if (!s_mock.initialized) {
        return FWUAL_ERR_INVALID_STATE;
    }

    s_mock.lifecycle_state = FWUAL_STATE_ROLLED_BACK;
    return FWUAL_OK;
}

fwual_state_t fwual_get_state(void)
{
    if (!s_mock.initialized) {
        return FWUAL_STATE_FAILED;
    }
    return s_mock.lifecycle_state;
}

fwual_result_t fwual_list_installed(fwual_installed_image_t *list, size_t *in_out_count)
{
    if (list == NULL || in_out_count == NULL) {
        return FWUAL_ERR_INVALID_PARAM;
    }
    if (!s_mock.initialized) {
        return FWUAL_ERR_INVALID_STATE;
    }

    *in_out_count = 0U;
    return FWUAL_OK;
}

bool fwual_is_image_staged(fwual_session_t *session, fwual_image_id_t image_id)
{
    fwual_mock_image_t *slot = NULL;

    if (session == NULL || session != &s_mock.session) {
        return false;
    }
    if (!s_mock.session.active) {
        return false;
    }

    slot = find_active_image(image_id);
    if (slot == NULL) {
        return false;
    }

    return slot->finalized && slot->verified;
}

void fwual_mock_simulate_reboot(void)
{
    s_mock.initialized = false;
    s_mock.session.active = false;
}
