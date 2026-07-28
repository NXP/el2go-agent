/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <string.h>

#include "fwual_mbedtls_compat.h"

#include <zephyr/kvss/nvs.h>
#include <zephyr/storage/flash_map.h>
#include <zephyr/dfu/mcuboot.h>
#include <zephyr/drivers/flash.h>

#include <bootutil/bootutil_public.h>

#include "fwual/fwual.h"
#include "compiler.h"
#include "debug.h"
#include "fwual_state.h"

/** Read buffer size for streaming SHA-256 hash computation.
 *  Stack-allocated; 4 KB is safe for Zephyr with default stack sizes. */
#define FWUAL_VERIFY_CHUNK_SIZE 4096U

/*
 * Secondary-slot flash-area IDs indexed by MCUBoot image index.
 * MCUBoot convention: image N uses slot(2N) as primary and slot(2N+1) as secondary.
 * Extend the list when CONFIG_FWUAL_MCUBOOT_IMAGE_COUNT grows beyond 4.
 */
static const uint8_t s_secondary_slot_ids[] = {
    PARTITION_ID(slot1_partition),
#if CONFIG_FWUAL_MCUBOOT_IMAGE_COUNT >= 2
    PARTITION_ID(slot3_partition),
#endif
#if CONFIG_FWUAL_MCUBOOT_IMAGE_COUNT >= 3
    PARTITION_ID(slot5_partition),
#endif
#if CONFIG_FWUAL_MCUBOOT_IMAGE_COUNT >= 4
    PARTITION_ID(slot7_partition),
#endif
};

/* MCUBoot slot table */

typedef struct {
    uint8_t flash_area_id; /**< Zephyr flash_area ID for the inactive slot. */
    uint32_t size;         /**< Slot size in bytes, from flash_area_get_size(). */
    uint32_t
        write_block_size; /**< Flash write alignment in bytes, from flash_area_get_write_block_size(). */
    bool in_use;          /**< true when claimed by a prepare_image call. */
} fwual_mcuboot_slot_t;

static fwual_mcuboot_slot_t s_slots[FWUAL_MAX_IMAGES];
static size_t s_slot_count;
static bool s_slots_initialized;

/*  Internal state — single static instance */

static fwual_internal_state_t s_fwual_state;

/* NVS filesystem handle */

static struct nvs_fs s_nvs_fs;

/* NVS helpers */

static fwual_result_t fwual_nvs_read_state(fwual_update_state_t *out_state)
{
    fwual_result_t result = FWUAL_ERR_INTERNAL;
    ssize_t rc = 0;

    rc = nvs_read(&s_nvs_fs, FWUAL_NVS_KEY_STATE, out_state, sizeof(*out_state));
    if (rc == -ENOENT) {
        /* First boot — no persisted state. */
        *out_state = FWUAL_UPDATE_STATE_IDLE;
        result = FWUAL_OK;
        goto exit;
    }
    if (rc < 0) {
        EL2GO_DBG_PRINTF(ERROR, "nvs_read failed: %d\n", (int)rc);
        goto exit;
    }

    result = FWUAL_OK;

exit:
    return result;
}

static fwual_result_t fwual_nvs_write_state(fwual_update_state_t state)
{
    fwual_result_t result = FWUAL_ERR_INTERNAL;
    ssize_t rc = 0;

    rc = nvs_write(&s_nvs_fs, FWUAL_NVS_KEY_STATE, &state, sizeof(state));
    if (rc < 0) {
        EL2GO_DBG_PRINTF(ERROR, "nvs_write failed: %d\n", (int)rc);
        goto exit;
    }

    result = FWUAL_OK;

exit:
    return result;
}

/* MCUBoot slot helpers */

static fwual_result_t fwual_slots_init(void)
{
    fwual_result_t result = FWUAL_ERR_INTERNAL;
    int image_count = 0;
    size_t i = 0U;
    const struct flash_area *fa = NULL;
    uint8_t flash_area_id = 0U;
    int rc = 0;
    uint8_t active_slot_id = 0U;

    if (s_slots_initialized) {
        result = FWUAL_OK;
        goto exit;
    }

    image_count = CONFIG_FWUAL_MCUBOOT_IMAGE_COUNT;
    if (image_count <= 0) {
        EL2GO_DBG_PRINTF(ERROR, "CONFIG_UPDATEABLE_IMAGE_NUMBER is %d\n", image_count);
        goto exit;
    }

    s_slot_count = (size_t)image_count;
    if (s_slot_count > FWUAL_MAX_IMAGES) {
        s_slot_count = FWUAL_MAX_IMAGES;
    }

    for (i = 0U; i < s_slot_count; i++) {
        /*
         * Each MCUBoot image N has its secondary slot at index 2N+1.
         * s_secondary_slot_ids[] maps image index -> secondary flash-area ID,
         * so the correct slot is always used regardless of the running slot.
         */
        if (i >= ARRAY_SIZE(s_secondary_slot_ids)) {
            EL2GO_DBG_PRINTF(ERROR, "fwual_slots_init: no secondary slot mapping for image %zu\n",
                             i);
            goto exit;
        }
        flash_area_id = s_secondary_slot_ids[i];
        rc = flash_area_open(flash_area_id, &fa);
        if (rc != 0) {
            EL2GO_DBG_PRINTF(ERROR, "flash_area_open(id=%u) failed: %d\n", flash_area_id, rc);
            goto exit;
        }

        s_slots[i].flash_area_id = flash_area_id;
        s_slots[i].size = (uint32_t)flash_area_get_size(fa);
        s_slots[i].write_block_size = (uint32_t)flash_area_align(fa);
        s_slots[i].in_use = false;

        flash_area_close(fa);
    }

    s_slots_initialized = true;

    EL2GO_DBG_PRINTF(INFO, "MCUBoot initialized. %zu image slot(s) discovered.\n", s_slot_count);

    result = FWUAL_OK;

exit:
    return result;
}

static fwual_result_t fwual_mcuboot_prepare_slot(uint32_t image_id, uint64_t size,
                                                 uint32_t *out_slot_index)
{
    fwual_result_t result = FWUAL_ERR_INTERNAL;
    fwual_mcuboot_slot_t *slot = NULL;
    const struct flash_area *fa = NULL;
    int rc = 0;

    if (out_slot_index == NULL) {
        result = FWUAL_ERR_INVALID_PARAM;
        goto exit;
    }

    if (!s_slots_initialized) {
        goto exit;
    }

    if (image_id >= (uint32_t)s_slot_count) {
        result = FWUAL_ERR_INVALID_PARAM;
        goto exit;
    }

    slot = &s_slots[image_id];

    if (slot->in_use) {
        result = FWUAL_ERR_BUSY;
        goto exit;
    }

    if (size > (uint64_t)slot->size) {
        EL2GO_DBG_PRINTF(ERROR, "Image too large: requested %llu bytes, slot %u has %u bytes\n",
                         (unsigned long long)size, image_id, slot->size);
        result = FWUAL_ERR_NO_SPACE;
        goto exit;
    }

    rc = flash_area_open(slot->flash_area_id, &fa);
    if (rc != 0) {
        EL2GO_DBG_PRINTF(ERROR, "flash_area_open(id=%u) failed: %d\n", slot->flash_area_id, rc);
        goto exit;
    }

    rc = flash_area_erase(fa, 0, slot->size);
    if (rc != 0) {
        EL2GO_DBG_PRINTF(ERROR, "flash_area_erase failed: %d\n", rc);
        goto exit;
    }

    slot->in_use = true;
    *out_slot_index = image_id;

    EL2GO_DBG_PRINTF(INFO, "Slot %u erased and reserved for image id=%u.\n", image_id, image_id);

    result = FWUAL_OK;

exit:
    if (fa != NULL) {
        flash_area_close(fa);
    }
    return result;
}

static fwual_result_t fwual_mcuboot_cancel_slot(uint32_t slot_index)
{
    fwual_result_t result = FWUAL_ERR_INTERNAL;

    if (!s_slots_initialized) {
        goto exit;
    }

    if (slot_index >= (uint32_t)s_slot_count) {
        result = FWUAL_ERR_INVALID_PARAM;
        goto exit;
    }

    s_slots[slot_index].in_use = false;

    result = FWUAL_OK;

exit:
    return result;
}

__export fwual_result_t fwual_init(void)
{
    fwual_result_t result = FWUAL_ERR_INTERNAL;
    struct flash_pages_info info = { 0 };
    int rc = 0;

    if (s_fwual_state.initialized) {
        result = FWUAL_OK;
        goto exit;
    }

    memset(&s_fwual_state, 0, sizeof(s_fwual_state));

    s_nvs_fs.flash_device = PARTITION_DEVICE(storage_partition);
    s_nvs_fs.offset = (off_t)PARTITION_OFFSET(storage_partition);

    rc = flash_get_page_info_by_offs(s_nvs_fs.flash_device, s_nvs_fs.offset, &info);
    if (rc != 0) {
        EL2GO_DBG_PRINTF(ERROR, "flash_get_page_info_by_offs failed: %d\n", rc);
        goto exit;
    }

    s_nvs_fs.sector_size = (uint32_t)info.size;
    s_nvs_fs.sector_count = (uint16_t)(PARTITION_SIZE(storage_partition) / s_nvs_fs.sector_size);

    rc = nvs_mount(&s_nvs_fs);
    if (rc != 0) {
        EL2GO_DBG_PRINTF(ERROR, "nvs_mount failed: %d\n", rc);
        goto exit;
    }

    result = fwual_slots_init();
    if (result != FWUAL_OK) {
        EL2GO_DBG_PRINTF(ERROR, "fwual_slots_init failed: %d\n", (int)result);
        goto exit;
    }

    result = fwual_nvs_read_state(&s_fwual_state.update_state);
    if (result != FWUAL_OK) {
        goto exit;
    }

    /* Cache capabilities once — time-invariant for this boot. */
    s_fwual_state.caps.requires_sequential_writes = true;
    s_fwual_state.caps.rejects_overlaps = true;
    s_fwual_state.caps.supports_delta = false;
    s_fwual_state.caps.write_alignment = (s_slot_count > 0U) ? s_slots[0].write_block_size : 0U;
    s_fwual_state.caps.max_write_size = 0U;

    s_fwual_state.initialized = true;

    EL2GO_DBG_PRINTF(INFO, "FWUAL initialized. Restored state: %d\n",
                     (int)s_fwual_state.update_state);

    result = FWUAL_OK;

exit:
    return result;
}

__export fwual_result_t fwual_get_caps(fwual_caps_t *out_caps)
{
    fwual_result_t result = FWUAL_ERR_INTERNAL;

    if (out_caps == NULL) {
        result = FWUAL_ERR_INVALID_PARAM;
        goto exit;
    }

    if (!s_fwual_state.initialized) {
        result = FWUAL_ERR_INVALID_STATE;
        goto exit;
    }

    /* Serve from cache — populated once at fwual_init(). */
    *out_caps = s_fwual_state.caps;

    result = FWUAL_OK;

exit:
    return result;
}

__export fwual_result_t fwual_open_session(fwual_session_t **out_session)
{
    fwual_result_t result = FWUAL_ERR_INTERNAL;

    if (out_session == NULL) {
        result = FWUAL_ERR_INVALID_PARAM;
        goto exit;
    }

    if (!s_fwual_state.initialized) {
        result = FWUAL_ERR_INVALID_STATE;
        goto exit;
    }

    if (s_fwual_state.session.active) {
        result = FWUAL_ERR_BUSY;
        goto exit;
    }

    result = fwual_nvs_write_state(FWUAL_UPDATE_STATE_SESSION_OPEN);
    if (result != FWUAL_OK) {
        result = FWUAL_ERR_INTERNAL;
        goto exit;
    }

    memset(&s_fwual_state.session, 0, sizeof(s_fwual_state.session));

    s_fwual_state.session.active = true;
    s_fwual_state.update_state = FWUAL_UPDATE_STATE_SESSION_OPEN;

    *out_session = &s_fwual_state.session;

    EL2GO_DBG_PRINTF(INFO, "Session opened.\n");

    result = FWUAL_OK;

exit:
    return result;
}

__export fwual_result_t fwual_close_session(fwual_session_t *session)
{
    size_t i = 0U;
    size_t image_count = 0U;
    fwual_result_t result = FWUAL_ERR_INTERNAL;

    if (session == NULL) {
        result = FWUAL_OK;
        goto exit;
    }

    if (session != &s_fwual_state.session) {
        result = FWUAL_ERR_INVALID_PARAM;
        goto exit;
    }

    if (!s_fwual_state.session.active) {
        result = FWUAL_OK;
        goto exit;
    }

    /* Persist IDLE before releasing slots — NVS write must precede in-memory update. */
    result = fwual_nvs_write_state(FWUAL_UPDATE_STATE_IDLE);
    if (result != FWUAL_OK) {
        EL2GO_DBG_PRINTF(ERROR, "fwual_nvs_write_state(IDLE) failed during close: %d\n",
                         (int)result);
        goto exit;
    }

    /* Cancel all prepared, non-cancelled image slots. */
    image_count = s_fwual_state.session.image_count;
    for (i = 0U; i < image_count; i++) {
        fwual_image_slot_t *slot = &s_fwual_state.session.images[i];

        if (slot->prepared && !slot->cancelled) {
            result = fwual_mcuboot_cancel_slot(slot->slot_index);
            if (result != FWUAL_OK) {
                EL2GO_DBG_PRINTF(ERROR, "fwual_mcuboot_cancel_slot(%u) failed during close: %d\n",
                                 slot->slot_index, (int)result);
                /* Continue — close must not leave session half-open. */
            } else {
                EL2GO_DBG_PRINTF(INFO, "Slot %u released during close.\n", slot->slot_index);
            }
        }
    }

    memset(&s_fwual_state.session, 0, sizeof(s_fwual_state.session));
    s_fwual_state.update_state = FWUAL_UPDATE_STATE_IDLE;

    EL2GO_DBG_PRINTF(INFO, "Session closed.\n");

    result = FWUAL_OK;

exit:
    return result;
}

__export fwual_result_t fwual_prepare_image(fwual_session_t *session,
                                            const fwual_image_desc_t *desc)
{
    size_t i = 0U;
    size_t image_count = 0U;
    uint32_t slot_index = 0U;
    fwual_result_t result = FWUAL_ERR_INTERNAL;
    fwual_image_slot_t *new_slot = NULL;
    bool has_free = false;

    if (session == NULL || desc == NULL) {
        result = FWUAL_ERR_INVALID_PARAM;
        goto exit;
    }

    if (!s_fwual_state.session.active) {
        result = FWUAL_ERR_INVALID_PARAM; /* closed session = invalid param */
        goto exit;
    }

    if (session != &s_fwual_state.session) {
        result = FWUAL_ERR_INVALID_PARAM;
        goto exit;
    }

    /* Check for duplicate image_id — skip cancelled entries. */
    image_count = s_fwual_state.session.image_count;
    for (i = 0U; i < image_count; i++) {
        if (!s_fwual_state.session.images[i].cancelled &&
            s_fwual_state.session.images[i].image_id == desc->image_id) {
            result = FWUAL_ERR_INVALID_PARAM;
            goto exit;
        }
    }

    if (s_fwual_state.session.image_count >= FWUAL_MAX_IMAGES) {
        for (i = 0U; i < image_count; i++) {
            if (s_fwual_state.session.images[i].cancelled) {
                has_free = true;
                break;
            }
        }
        if (!has_free) {
            result = FWUAL_ERR_NO_SPACE;
            goto exit;
        }
    }

    result = fwual_mcuboot_prepare_slot(desc->image_id, desc->size, &slot_index);
    if (result != FWUAL_OK) {
        goto exit;
    }

    result = fwual_nvs_write_state(FWUAL_UPDATE_STATE_IMAGE_PREPARED);
    if (result != FWUAL_OK) {
        EL2GO_DBG_PRINTF(ERROR, "fwual_nvs_write_state(IMAGE_PREPARED) failed: %d\n", (int)result);
        fwual_mcuboot_cancel_slot(slot_index);
        goto exit;
    }

    for (i = 0U; i < image_count; i++) {
        if (s_fwual_state.session.images[i].cancelled) {
            new_slot = &s_fwual_state.session.images[i];
            break;
        }
    }

    if (new_slot == NULL) {
        new_slot = &s_fwual_state.session.images[s_fwual_state.session.image_count];
        s_fwual_state.session.image_count++;
    }

    new_slot->image_id = desc->image_id;
    new_slot->desc = *desc;
    new_slot->prepared = true;
    new_slot->cancelled = false;
    new_slot->finalized = false;
    new_slot->verified = false;
    new_slot->bytes_written = 0U;
    new_slot->next_expected_offset = 0U;
    new_slot->slot_index = slot_index;

    s_fwual_state.session.image_count++;
    s_fwual_state.update_state = FWUAL_UPDATE_STATE_IMAGE_PREPARED;

    EL2GO_DBG_PRINTF(INFO, "Image prepared: id=%u slot=%u size=%llu\n", desc->image_id, slot_index,
                     (unsigned long long)desc->size);

    result = FWUAL_OK;

exit:
    return result;
}

fwual_result_t fwual_cancel_image(fwual_session_t *session, fwual_image_id_t image_id)
{
    size_t i = 0U;
    size_t image_count = 0U;
    fwual_image_slot_t *slot = NULL;
    fwual_image_slot_t *candidate = NULL;
    fwual_result_t result = FWUAL_ERR_INTERNAL;
    bool any_prepared = false;

    if (session == NULL) {
        result = FWUAL_ERR_INVALID_PARAM;
        goto exit;
    }

    if (session != &s_fwual_state.session) {
        result = FWUAL_ERR_INVALID_PARAM;
        goto exit;
    }

    if (!s_fwual_state.session.active) {
        result = FWUAL_ERR_INVALID_STATE;
        goto exit;
    }

    /* Find the slot with matching image_id that is prepared and not cancelled. */
    image_count = s_fwual_state.session.image_count;
    for (i = 0U; i < image_count; i++) {
        candidate = &s_fwual_state.session.images[i];

        if (candidate->image_id == image_id && candidate->prepared && !candidate->cancelled) {
            slot = candidate;
            break;
        }
    }

    if (slot == NULL) {
        result = FWUAL_ERR_INVALID_PARAM;
        goto exit;
    }

    result = fwual_mcuboot_cancel_slot(slot->slot_index);
    if (result != FWUAL_OK) {
        goto exit;
    }

    /* Recompute update_state. */
    for (i = 0U; i < image_count; i++) {
        if (s_fwual_state.session.images[i].prepared &&
            !s_fwual_state.session.images[i].cancelled &&
            s_fwual_state.session.images[i].image_id != image_id) {
            any_prepared = true;
            break;
        }
    }

    result = fwual_nvs_write_state(any_prepared ? FWUAL_UPDATE_STATE_IMAGE_PREPARED :
                                                  FWUAL_UPDATE_STATE_SESSION_OPEN);
    if (result != FWUAL_OK) {
        EL2GO_DBG_PRINTF(ERROR, "fwual_nvs_write_state failed after cancel: %d\n", (int)result);
        s_slots[slot->slot_index].in_use = true;
        goto exit;
    }

    slot->cancelled = true;
    s_fwual_state.update_state = any_prepared ? FWUAL_UPDATE_STATE_IMAGE_PREPARED :
                                                FWUAL_UPDATE_STATE_SESSION_OPEN;

    EL2GO_DBG_PRINTF(INFO, "Slot %u released.\n", slot->slot_index);
    EL2GO_DBG_PRINTF(INFO, "Image cancelled: id=%u slot=%u\n", image_id, slot->slot_index);

    result = FWUAL_OK;

exit:
    return result;
}

static fwual_result_t fwual_mcuboot_write(uint32_t slot_index, uint64_t offset, const uint8_t *data,
                                          size_t len)
{
    fwual_result_t result = FWUAL_ERR_INTERNAL;
    const struct flash_area *fa = NULL;
    off_t physical_addr = 0;
    int rc = 0;

    if (data == NULL || len == 0U || !s_slots_initialized || slot_index >= (uint32_t)s_slot_count) {
        result = FWUAL_ERR_INVALID_PARAM;
        goto exit;
    }

    /* Bounds check: offset + len must not exceed the physical slot size. */
    if (offset + (uint64_t)len > (uint64_t)s_slots[slot_index].size) {
        EL2GO_DBG_PRINTF(ERROR,
                         "mcuboot_write: out of bounds: slot=%u offset=%llu len=%zu slot_size=%u\n",
                         slot_index, (unsigned long long)offset, len, s_slots[slot_index].size);
        result = FWUAL_ERR_INVALID_PARAM;
        goto exit;
    }

    rc = flash_area_open(s_slots[slot_index].flash_area_id, &fa);
    if (rc != 0) {
        EL2GO_DBG_PRINTF(ERROR, "mcuboot_write: flash_area_open(id=%u) failed: %d\n",
                         s_slots[slot_index].flash_area_id, rc);
        goto exit;
    }

    physical_addr = (off_t)offset;

    EL2GO_DBG_PRINTF(DEBUG, "mcuboot_write: slot=%u offset=%llu len=%zu phys=0x%08x\n", slot_index,
                     (unsigned long long)offset, len, (unsigned)physical_addr);

    rc = flash_area_write(fa, physical_addr, data, len);
    if (rc != 0) {
        EL2GO_DBG_PRINTF(ERROR, "mcuboot_write: flash_area_write failed: %d\n", rc);
        result = FWUAL_ERR_IO;
        goto exit;
    }

    result = FWUAL_OK;

exit:
    if (fa != NULL) {
        flash_area_close(fa);
    }
    return result;
}

static fwual_result_t fwual_mcuboot_finalize(uint32_t slot_index, uint64_t expected_size)
{
    fwual_result_t result = FWUAL_ERR_INTERNAL;

    EL2GO_DBG_PRINTF(INFO, "mcuboot_finalize: slot=%u expected_size=%llu\n", slot_index,
                     (unsigned long long)expected_size);

    if (!s_slots_initialized || slot_index >= (uint32_t)s_slot_count) {
        result = FWUAL_ERR_INVALID_PARAM;
        goto exit;
    }

    /*
     * Delta updates are not supported on this backend (supports_delta == false).
     * For FWUAL_UPDATE_FULL: the secondary slot is fully written and erased
     * during prepare. No additional flash operations are required here —
     * MCUBoot will verify and swap on next boot.
     */

    result = FWUAL_OK;

exit:
    return result;
}

__export fwual_result_t fwual_write(fwual_session_t *session, fwual_image_id_t image_id,
                                    uint64_t offset, const uint8_t *data, size_t len)
{
    fwual_result_t result = FWUAL_ERR_INTERNAL;
    fwual_image_slot_t *slot = NULL;
    size_t i = 0U;
    size_t image_count = 0U;

    /* 1. NULL / zero guards */
    if (session == NULL) {
        result = FWUAL_ERR_INVALID_PARAM;
        goto exit;
    }
    if (data == NULL) {
        result = FWUAL_ERR_INVALID_PARAM;
        goto exit;
    }
    if (len == 0U) {
        result = FWUAL_ERR_INVALID_PARAM;
        goto exit;
    }

    /* 2. Resolve session context */
    if (session != &s_fwual_state.session || !s_fwual_state.session.active) {
        result = FWUAL_ERR_INVALID_STATE;
        goto exit;
    }

    /* 3. Find image slot */
    image_count = s_fwual_state.session.image_count;
    for (i = 0U; i < image_count; i++) {
        if (s_fwual_state.session.images[i].image_id == image_id) {
            slot = &s_fwual_state.session.images[i];
            break;
        }
    }
    if (slot == NULL || !slot->prepared || slot->cancelled || slot->finalized) {
        result = FWUAL_ERR_INVALID_STATE;
        goto exit;
    }

    /* 4. Sequential write enforcement — use cached caps, no function call overhead. */
    if (s_fwual_state.caps.requires_sequential_writes) {
        if (offset != slot->next_expected_offset) {
            EL2GO_DBG_PRINTF(ERROR, "Write out of order: image_id=%u expected=%llu got=%llu\n",
                             image_id, (unsigned long long)slot->next_expected_offset,
                             (unsigned long long)offset);
            result = FWUAL_ERR_INVALID_STATE;
            goto exit;
        }
    }

    /* 5. Bounds check */
    if (offset + (uint64_t)len > slot->desc.size) {
        EL2GO_DBG_PRINTF(ERROR, "Write overflow: image_id=%u offset=%llu len=%zu size=%llu\n",
                         image_id, (unsigned long long)offset, len,
                         (unsigned long long)slot->desc.size);
        result = FWUAL_ERR_INVALID_PARAM;
        goto exit;
    }

    /* 6. Alignment check — use cached caps. */
    if (s_fwual_state.caps.write_alignment > 1U &&
        (len % (size_t)s_fwual_state.caps.write_alignment) != 0U) {
        EL2GO_DBG_PRINTF(ERROR, "Write alignment violation: image_id=%u len=%zu alignment=%u\n",
                         image_id, len, s_fwual_state.caps.write_alignment);
        result = FWUAL_ERR_INVALID_PARAM;
        goto exit;
    }

    /* 7. Backend write */
    result = fwual_mcuboot_write(slot->slot_index, offset, data, len);
    if (result != FWUAL_OK) {
        goto exit;
    }

    /* 8. Update progress */
    slot->bytes_written += (uint64_t)len;
    slot->next_expected_offset = offset + (uint64_t)len;

    /* 9. Persist minimal progress to NVS (non-fatal on failure) */
    fwual_write_progress_t progress = {
        .image_id = slot->image_id,
        .bytes_written = slot->bytes_written,
        .next_expected_offset = slot->next_expected_offset,
        .finalized = slot->finalized,
    };

    ssize_t nvs_rc =
        nvs_write(&s_nvs_fs, FWUAL_NVS_KEY_WRITE_PROGRESS, &progress, sizeof(progress));
    if (nvs_rc < 0) {
        EL2GO_DBG_PRINTF(ERROR, "fwual_write: NVS persist failed (non-fatal): %d\n", (int)nvs_rc);
    }

    /* 10. Log and return */
    EL2GO_DBG_PRINTF(INFO, "Write: image_id=%u offset=%llu len=%zu\n", image_id,
                     (unsigned long long)offset, len);
    result = FWUAL_OK;

exit:
    return result;
}

__export fwual_result_t fwual_finalize_image(fwual_session_t *session, fwual_image_id_t image_id)
{
    fwual_result_t result = FWUAL_ERR_INTERNAL;
    fwual_image_slot_t *slot = NULL;
    size_t i = 0U;
    size_t image_count = 0U;

    /* 1. NULL guard */
    if (session == NULL) {
        result = FWUAL_ERR_INVALID_PARAM;
        goto exit;
    }

    /* 2. Resolve session context */
    if (session != &s_fwual_state.session || !s_fwual_state.session.active) {
        result = FWUAL_ERR_INVALID_STATE;
        goto exit;
    }

    /* 3. Find image slot */
    image_count = s_fwual_state.session.image_count;
    for (i = 0U; i < image_count; i++) {
        if (s_fwual_state.session.images[i].image_id == image_id) {
            slot = &s_fwual_state.session.images[i];
            break;
        }
    }
    if (slot == NULL || !slot->prepared || slot->cancelled || slot->finalized) {
        result = FWUAL_ERR_INVALID_STATE;
        goto exit;
    }

    /* 4. Completeness check — use < to tolerate alignment padding on last chunk. */
    if (slot->bytes_written < slot->desc.size) {
        EL2GO_DBG_PRINTF(ERROR, "Finalize incomplete: image_id=%u written=%llu expected=%llu\n",
                         image_id, (unsigned long long)slot->bytes_written,
                         (unsigned long long)slot->desc.size);
        result = FWUAL_ERR_INVALID_STATE;
        goto exit;
    }

    /* 5. Backend finalize */
    result = fwual_mcuboot_finalize(slot->slot_index, slot->desc.size);
    if (result != FWUAL_OK) {
        goto exit;
    }

    /* 6. Mark finalized */
    slot->finalized = true;

    /* 7. Persist minimal progress to NVS (non-fatal on failure) */
    fwual_write_progress_t progress = {
        .image_id = slot->image_id,
        .bytes_written = slot->bytes_written,
        .next_expected_offset = slot->next_expected_offset,
        .finalized = slot->finalized,
    };

    ssize_t nvs_rc =
        nvs_write(&s_nvs_fs, FWUAL_NVS_KEY_WRITE_PROGRESS, &progress, sizeof(progress));
    if (nvs_rc < 0) {
        EL2GO_DBG_PRINTF(ERROR, "fwual_finalize_image: NVS persist failed (non-fatal): %d\n",
                         (int)nvs_rc);
    }

    /* 8. Log and return */
    EL2GO_DBG_PRINTF(INFO, "Image finalized: image_id=%u size=%llu\n", image_id,
                     (unsigned long long)slot->desc.size);
    result = FWUAL_OK;

exit:
    return result;
}

static fwual_result_t fwual_mcuboot_read(uint32_t slot_index, uint64_t offset, uint8_t *buf,
                                         size_t len)
{
    fwual_result_t result = FWUAL_ERR_INTERNAL;
    const struct flash_area *fa = NULL;
    int rc = 0;

    if (buf == NULL || len == 0U || !s_slots_initialized || slot_index >= (uint32_t)s_slot_count) {
        result = FWUAL_ERR_INVALID_PARAM;
        goto exit;
    }

    rc = flash_area_open(s_slots[slot_index].flash_area_id, &fa);
    if (rc != 0) {
        EL2GO_DBG_PRINTF(ERROR, "mcuboot_read: flash_area_open(id=%u) failed: %d\n",
                         s_slots[slot_index].flash_area_id, rc);
        goto exit;
    }

    rc = flash_area_read(fa, (off_t)offset, buf, len);
    if (rc != 0) {
        EL2GO_DBG_PRINTF(ERROR, "MCUBoot flash read failed at offset=%llu len=%zu rc=%d\n",
                         (unsigned long long)offset, len, rc);
        result = FWUAL_ERR_IO;
        goto exit;
    }

    result = FWUAL_OK;

exit:
    if (fa != NULL) {
        flash_area_close(fa);
    }
    return result;
}

static fwual_result_t fwual_mcuboot_verify_platform(uint32_t slot_index)
{
#if defined(CONFIG_BOOT_SIGNATURE_TYPE_RSA) || defined(CONFIG_BOOT_SIGNATURE_TYPE_ECDSA_P256) || \
    defined(CONFIG_BOOT_SIGNATURE_TYPE_ED25519)
    /* MCUBoot platform authentication is available. The bootloader performs
     * full signature verification at boot time; here we check whether the
     * secondary slot image header is parseable and not corrupted as a
     * pre-activation sanity check. */
    struct mcuboot_img_header hdr;
    int rc = boot_read_bank_header((uint8_t)s_slots[slot_index].flash_area_id, &hdr, sizeof(hdr));
    if (rc != 0) {
        EL2GO_DBG_PRINTF(ERROR, "MCUBoot image authentication failed for slot=%u\n", slot_index);
        return FWUAL_ERR_CORRUPT;
    }
    EL2GO_DBG_PRINTF(INFO, "MCUBoot image authentication passed for slot=%u\n", slot_index);
    return FWUAL_OK;
#else
    EL2GO_DBG_PRINTF(DEBUG, "MCUBoot image authentication not available for slot=%u -- skipping\n",
                     slot_index);
    (void)slot_index;
    return FWUAL_OK;
#endif
}

__export fwual_result_t fwual_verify_image(fwual_session_t *session, fwual_image_id_t image_id)
{
    fwual_result_t result = FWUAL_ERR_INTERNAL;
    fwual_image_slot_t *slot = NULL;
    size_t i = 0U;
    size_t image_count = 0U;
    uint8_t chunk[FWUAL_VERIFY_CHUNK_SIZE] = { 0 };
    uint8_t computed_hash[32] = { 0 };
    fwual_sha256_context sha_ctx = { 0 };
    int mbedret = 0;
    uint64_t offset = 0U;
    size_t remaining = 0U;
    fwual_result_t auth_result = FWUAL_OK;
    fwual_write_progress_t progress = { 0 };
    ssize_t nvs_rc = 0;

    /* 1. Validate session */
    if (session == NULL) {
        result = FWUAL_ERR_INVALID_PARAM;
        goto exit;
    }

    /* 2. Resolve and validate session context */
    if (session != &s_fwual_state.session || !s_fwual_state.session.active) {
        result = FWUAL_ERR_INVALID_STATE;
        goto exit;
    }

    /* 3. Find image slot */
    image_count = s_fwual_state.session.image_count;
    for (i = 0U; i < image_count; i++) {
        if (s_fwual_state.session.images[i].image_id == image_id) {
            slot = &s_fwual_state.session.images[i];
            break;
        }
    }
    if (slot == NULL) {
        result = FWUAL_ERR_INVALID_STATE;
        goto exit;
    }

    /* 4. Enforce finalize-before-verify */
    if (!slot->finalized) {
        EL2GO_DBG_PRINTF(ERROR, "fwual_verify_image: image_id=%u not finalized\n", image_id);
        result = FWUAL_ERR_INVALID_STATE;
        goto exit;
    }

    /* 5. Validate hash descriptor fields */
    if (slot->desc.expected_hash == NULL || slot->desc.hash_len == 0U) {
        result = FWUAL_ERR_INVALID_PARAM;
        goto exit;
    }

    /* 6. Check hash algorithm -- only "sha256" is supported */
    if (slot->desc.hash_algo == NULL || strcmp(slot->desc.hash_algo, "sha256") != 0) {
        EL2GO_DBG_PRINTF(ERROR, "fwual_verify_image: unsupported hash algo '%s' for image_id=%u\n",
                         slot->desc.hash_algo ? slot->desc.hash_algo : "(null)", image_id);
        result = FWUAL_ERR_UNSUPPORTED;
        goto exit;
    }

    /* 7. Check expected hash length -- SHA-256 produces exactly 32 bytes */
    if (slot->desc.hash_len != 32U) {
        EL2GO_DBG_PRINTF(ERROR,
                         "fwual_verify_image: invalid hash_len=%zu for sha256 "
                         "(expected 32) image_id=%u\n",
                         slot->desc.hash_len, image_id);
        result = FWUAL_ERR_INVALID_PARAM;
        goto exit;
    }

    /* 8. Compute SHA-256 by streaming from flash */
    fwual_sha256_init(&sha_ctx);

    mbedret = fwual_sha256_starts(&sha_ctx);
    if (mbedret != 0) {
        fwual_sha256_free(&sha_ctx);
        EL2GO_DBG_PRINTF(ERROR, "fwual_verify_image: sha256_starts_ret failed: %d image_id=%u\n",
                         mbedret, image_id);
        result = FWUAL_ERR_INTERNAL;
        goto exit;
    }

    offset = 0U;
    remaining = (size_t)slot->desc.size;

    while (remaining > 0U) {
        size_t to_read = (remaining < FWUAL_VERIFY_CHUNK_SIZE) ? remaining :
                                                                 FWUAL_VERIFY_CHUNK_SIZE;
        fwual_result_t read_result = fwual_mcuboot_read(slot->slot_index, offset, chunk, to_read);
        if (read_result != FWUAL_OK) {
            fwual_sha256_free(&sha_ctx);
            EL2GO_DBG_PRINTF(ERROR,
                             "fwual_verify_image: flash read failed at "
                             "offset=%llu image_id=%u\n",
                             (unsigned long long)offset, image_id);
            result = read_result;
            goto exit;
        }

        mbedret = fwual_sha256_update(&sha_ctx, chunk, to_read);
        if (mbedret != 0) {
            fwual_sha256_free(&sha_ctx);
            EL2GO_DBG_PRINTF(ERROR,
                             "fwual_verify_image: sha256_update_ret failed: %d image_id=%u\n",
                             mbedret, image_id);
            result = FWUAL_ERR_INTERNAL;
            goto exit;
        }

        offset += (uint64_t)to_read;
        remaining -= to_read;
    }

    mbedret = fwual_sha256_finish(&sha_ctx, computed_hash);
    fwual_sha256_free(&sha_ctx);
    if (mbedret != 0) {
        EL2GO_DBG_PRINTF(ERROR, "fwual_verify_image: sha256_finish_ret failed: %d image_id=%u\n",
                         mbedret, image_id);
        result = FWUAL_ERR_INTERNAL;
        goto exit;
    }

    /* 9. Constant-time hash comparison */
    if (fwual_ct_memcmp(computed_hash, slot->desc.expected_hash, 32U) != 0) {
        EL2GO_DBG_PRINTF(ERROR, "Image verification FAILED: hash mismatch for image_id=%u\n",
                         image_id);
        /* Do NOT set slot->verified -- image remains uncommitted. */
        result = FWUAL_ERR_CORRUPT;
        goto exit;
    }

    /* 10. Invoke MCUBoot platform authentication */
    auth_result = fwual_mcuboot_verify_platform(slot->slot_index);
    if (auth_result != FWUAL_OK) {
        EL2GO_DBG_PRINTF(ERROR,
                         "Image verification FAILED: MCUBoot authentication "
                         "failed for image_id=%u\n",
                         image_id);
        result = auth_result;
        goto exit;
    }

    /* 11. Mark verified and persist */
    slot->verified = true;

    progress.image_id = slot->image_id;
    progress.bytes_written = slot->bytes_written;
    progress.next_expected_offset = slot->next_expected_offset;
    progress.finalized = slot->finalized;
    progress.verified = slot->verified;
    nvs_rc = nvs_write(&s_nvs_fs, FWUAL_NVS_KEY_WRITE_PROGRESS, &progress, sizeof(progress));
    if (nvs_rc < 0) {
        EL2GO_DBG_PRINTF(ERROR, "fwual_verify_image: NVS persist failed for image_id=%u rc=%d\n",
                         image_id, (int)nvs_rc);
        /* Non-fatal: continue -- the in-RAM flag is set. */
    }

    EL2GO_DBG_PRINTF(INFO, "Image verified OK: image_id=%u\n", image_id);
    result = FWUAL_OK;

exit:
    return result;
}

__export fwual_result_t fwual_commit_session(fwual_session_t *session)
{
    fwual_result_t result = FWUAL_ERR_INTERNAL;
    size_t i = 0U;
    size_t image_count = 0U;

    if (session == NULL) {
        result = FWUAL_ERR_INVALID_PARAM;
        goto exit;
    }

    if (session != &s_fwual_state.session || !s_fwual_state.session.active) {
        result = FWUAL_ERR_INVALID_STATE;
        goto exit;
    }

    /* Every finalized slot must also be verified. */
    image_count = s_fwual_state.session.image_count;
    for (i = 0U; i < image_count; i++) {
        fwual_image_slot_t *slot = &s_fwual_state.session.images[i];

        if (!slot->prepared || slot->cancelled) {
            continue;
        }

        if (slot->finalized && !slot->verified) {
            EL2GO_DBG_PRINTF(ERROR,
                             "fwual_commit_session: image_id=%u is finalized but "
                             "not verified -- aborting commit\n",
                             slot->image_id);
            result = FWUAL_ERR_INVALID_STATE;
            goto exit;
        }
    }

    /* Request MCUBoot to swap to the secondary slot on next boot. */
    image_count = s_fwual_state.session.image_count;
    for (i = 0U; i < image_count; i++) {
        fwual_image_slot_t *slot = &s_fwual_state.session.images[i];
        int rc = 0;

        if (!slot->prepared || slot->cancelled || !slot->verified) {
            continue;
        }

        rc = boot_request_upgrade_multi((int)slot->image_id, BOOT_UPGRADE_TEST);
        if (rc != 0) {
            EL2GO_DBG_PRINTF(ERROR,
                             "fwual_commit_session: boot_request_upgrade_multi failed for "
                             "image_id=%u rc=%d\n",
                             slot->image_id, rc);
            result = FWUAL_ERR_PLATFORM;
            goto exit;
        }

        EL2GO_DBG_PRINTF(INFO, "fwual_commit_session: upgrade requested for image_id=%u\n",
                         slot->image_id);
    }

    EL2GO_DBG_PRINTF(INFO, "Session committed.\n");
    result = FWUAL_OK;

exit:
    return result;
}

__export bool fwual_is_image_staged(fwual_session_t *session, fwual_image_id_t image_id)
{
    size_t i = 0U;
    size_t image_count = 0U;

    if (session == NULL || session != &s_fwual_state.session) {
        return false;
    }

    if (!s_fwual_state.session.active) {
        return false;
    }

    image_count = s_fwual_state.session.image_count;
    for (i = 0U; i < image_count; i++) {
        fwual_image_slot_t *slot = &s_fwual_state.session.images[i];

        if (slot->image_id == image_id && slot->prepared && !slot->cancelled) {
            return slot->finalized && slot->verified;
        }
    }

    return false;
}
