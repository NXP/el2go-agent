/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <errno.h>
#include <string.h>

#include <zephyr/storage/flash_map.h>
#include <zephyr/kvss/nvs.h>
#include <zephyr/drivers/flash.h>
#include <zephyr/dfu/mcuboot.h>

#include "fwual_storage_mocks.h"

/* Secondary (upgrade) slot -- the only flash area FWUAL writes to. */
#define FAKE_SLOT_ID PARTITION_ID(slot1_partition)
#define FAKE_SLOT_SIZE (64U * 1024U)

static uint8_t s_slot_ram[FAKE_SLOT_SIZE];
static struct flash_area s_slot_fa;
static uint32_t s_slot_align = 1U;

static bool s_fail_next_erase;
static bool s_fail_next_write;
static bool s_fail_next_nvs_write;
static bool s_fail_next_boot_erase;

static uint32_t s_fail_nvs_write_key_mask;
static uint32_t s_fail_nvs_read_key_mask;
static bool s_short_next_nvs_write;
static bool s_fail_nvs_mount;
static bool s_fail_next_open;
static bool s_fail_next_read;
static bool s_fail_next_boot_request;
static bool s_fail_next_boot_confirm;
static bool s_fail_next_boot_header;

static bool s_boot_upgrade_pending;

/* Fixed-size key/value store, ids 0..NVS_MAX_KEYS-1. */
#define NVS_MAX_KEYS 8U
#define NVS_MAX_VALUE_SIZE 64U

typedef struct {
    bool present;
    size_t len;
    uint8_t data[NVS_MAX_VALUE_SIZE];
} nvs_fake_entry_t;

static nvs_fake_entry_t s_nvs_store[NVS_MAX_KEYS];

/* ---- reset / control API ------------------------------------------------ */

void fwual_fake_reset(void)
{
    memset(s_slot_ram, 0, sizeof(s_slot_ram));
    memset(&s_slot_fa, 0, sizeof(s_slot_fa));
    s_slot_fa.fa_id = FAKE_SLOT_ID;
    s_slot_fa.fa_off = 0;
    s_slot_fa.fa_size = sizeof(s_slot_ram);

    s_slot_align = 1U;

    s_fail_next_erase = false;
    s_fail_next_write = false;
    s_fail_next_nvs_write = false;
    s_fail_next_boot_erase = false;

    s_fail_nvs_write_key_mask = 0U;
    s_fail_nvs_read_key_mask = 0U;
    s_short_next_nvs_write = false;
    s_fail_nvs_mount = false;
    s_fail_next_open = false;
    s_fail_next_read = false;
    s_fail_next_boot_request = false;
    s_fail_next_boot_confirm = false;
    s_fail_next_boot_header = false;

    s_boot_upgrade_pending = false;

    memset(s_nvs_store, 0, sizeof(s_nvs_store));
}

void fwual_fake_set_align(uint32_t align)
{
    s_slot_align = (align == 0U) ? 1U : align;
}

void fwual_fake_fail_next_erase(bool arm)
{
    s_fail_next_erase = arm;
}

void fwual_fake_fail_next_write(bool arm)
{
    s_fail_next_write = arm;
}

void fwual_fake_fail_next_nvs_write(bool arm)
{
    s_fail_next_nvs_write = arm;
}

void fwual_fake_fail_next_boot_erase(bool arm)
{
    s_fail_next_boot_erase = arm;
}

void fwual_fake_fail_next_nvs_write_key(uint16_t id)
{
    if (id < NVS_MAX_KEYS) {
        s_fail_nvs_write_key_mask |= (1U << id);
    }
}

void fwual_fake_fail_next_nvs_read_key(uint16_t id)
{
    if (id < NVS_MAX_KEYS) {
        s_fail_nvs_read_key_mask |= (1U << id);
    }
}

void fwual_fake_short_next_nvs_write(bool arm)
{
    s_short_next_nvs_write = arm;
}

void fwual_fake_fail_nvs_mount(bool arm)
{
    s_fail_nvs_mount = arm;
}

void fwual_fake_fail_next_open(bool arm)
{
    s_fail_next_open = arm;
}

void fwual_fake_fail_next_read(bool arm)
{
    s_fail_next_read = arm;
}

void fwual_fake_fail_next_boot_request(bool arm)
{
    s_fail_next_boot_request = arm;
}

void fwual_fake_fail_next_boot_confirm(bool arm)
{
    s_fail_next_boot_confirm = arm;
}

void fwual_fake_fail_next_boot_header(bool arm)
{
    s_fail_next_boot_header = arm;
}

bool fwual_fake_nvs_seed(uint16_t id, const void *data, size_t len)
{
    if (data == NULL || id >= NVS_MAX_KEYS || len > NVS_MAX_VALUE_SIZE) {
        return false;
    }

    memcpy(s_nvs_store[id].data, data, len);
    s_nvs_store[id].len = len;
    s_nvs_store[id].present = true;
    return true;
}

bool fwual_fake_fault_pending(void)
{
    return s_fail_next_erase || s_fail_next_write || s_fail_next_nvs_write ||
           s_fail_next_boot_erase || (s_fail_nvs_write_key_mask != 0U) ||
           (s_fail_nvs_read_key_mask != 0U) || s_short_next_nvs_write || s_fail_next_open ||
           s_fail_next_read || s_fail_next_boot_request || s_fail_next_boot_confirm ||
           s_fail_next_boot_header;
}

bool fwual_fake_boot_pending(void)
{
    return s_boot_upgrade_pending;
}

const uint8_t *fwual_fake_slot_data(size_t *out_size)
{
    if (out_size != NULL) {
        *out_size = sizeof(s_slot_ram);
    }
    return s_slot_ram;
}

/* ---- flash_area_*() fakes ------------------------------------------------ */

int flash_area_open(uint8_t id, const struct flash_area **fa)
{
    if (fa == NULL) {
        return -EINVAL;
    }
    if (s_fail_next_open) {
        s_fail_next_open = false;
        return -EIO;
    }
    if (id != FAKE_SLOT_ID) {
        return -ENOENT;
    }
    *fa = &s_slot_fa;
    return 0;
}

/* flash_area_close() is a static inline in flash_map.h; nothing to fake. */

int flash_area_read(const struct flash_area *fa, off_t off, void *dst, size_t len)
{
    if (fa == NULL || dst == NULL) {
        return -EINVAL;
    }
    if (fa->fa_id != FAKE_SLOT_ID) {
        return -ENOENT;
    }
    if (s_fail_next_read) {
        s_fail_next_read = false;
        return -EIO;
    }
    if ((size_t)off + len > fa->fa_size) {
        return -EINVAL;
    }
    memcpy(dst, &s_slot_ram[off], len);
    return 0;
}

int flash_area_write(const struct flash_area *fa, off_t off, const void *src, size_t len)
{
    if (fa == NULL || src == NULL) {
        return -EINVAL;
    }
    if (fa->fa_id != FAKE_SLOT_ID) {
        return -ENOENT;
    }
    if (s_fail_next_write) {
        s_fail_next_write = false;
        return -EIO;
    }
    if ((size_t)off + len > fa->fa_size) {
        return -EINVAL;
    }
    memcpy(&s_slot_ram[off], src, len);
    return 0;
}

int flash_area_erase(const struct flash_area *fa, off_t off, size_t len)
{
    if (fa == NULL) {
        return -EINVAL;
    }
    if (fa->fa_id != FAKE_SLOT_ID) {
        return -ENOENT;
    }
    if (s_fail_next_erase) {
        s_fail_next_erase = false;
        return -EIO;
    }
    if ((size_t)off + len > fa->fa_size) {
        return -EINVAL;
    }
    memset(&s_slot_ram[off], 0xFF, len);
    return 0;
}

uint32_t flash_area_align(const struct flash_area *fa)
{
    (void)fa;
    return s_slot_align;
}

/* ---- nvs_*() fakes ------------------------------------------------------- */

int nvs_mount(struct nvs_fs *fs)
{
    (void)fs;
    if (s_fail_nvs_mount) {
        return -EIO;
    }
    return 0;
}

ssize_t nvs_read(struct nvs_fs *fs, uint16_t id, void *data, size_t len)
{
    (void)fs;

    if (data == NULL || id >= NVS_MAX_KEYS) {
        return -EINVAL;
    }
    if ((s_fail_nvs_read_key_mask & (1U << id)) != 0U) {
        s_fail_nvs_read_key_mask &= ~(1U << id);
        return -EIO;
    }
    if (!s_nvs_store[id].present) {
        return -ENOENT;
    }

    {
        size_t to_copy = (len < s_nvs_store[id].len) ? len : s_nvs_store[id].len;

        memcpy(data, s_nvs_store[id].data, to_copy);
        return (ssize_t)to_copy;
    }
}

ssize_t nvs_write(struct nvs_fs *fs, uint16_t id, const void *data, size_t len)
{
    bool unchanged = false;

    (void)fs;

    if (data == NULL || id >= NVS_MAX_KEYS) {
        return -EINVAL;
    }
    if (len > NVS_MAX_VALUE_SIZE) {
        return -EINVAL;
    }
    if (s_fail_next_nvs_write) {
        s_fail_next_nvs_write = false;
        return -EIO;
    }
    if ((s_fail_nvs_write_key_mask & (1U << id)) != 0U) {
        s_fail_nvs_write_key_mask &= ~(1U << id);
        return -EIO;
    }

    /* Like the real NVS, report 0 when the stored value is already identical. */
    unchanged = s_nvs_store[id].present && s_nvs_store[id].len == len &&
                memcmp(s_nvs_store[id].data, data, len) == 0;

    memcpy(s_nvs_store[id].data, data, len);
    s_nvs_store[id].len = len;
    s_nvs_store[id].present = true;

    if (s_short_next_nvs_write && len > 1U) {
        s_short_next_nvs_write = false;
        return (ssize_t)(len - 1U);
    }
    if (unchanged) {
        return 0;
    }
    return (ssize_t)len;
}

/* ---- MCUboot fakes -------------------------------------------------------- */

int boot_request_upgrade_multi(int image_index, int permanent)
{
    (void)image_index;
    (void)permanent;
    if (s_fail_next_boot_request) {
        s_fail_next_boot_request = false;
        return -EIO;
    }
    s_boot_upgrade_pending = true;
    return 0;
}

int boot_write_img_confirmed_multi(int image_index)
{
    (void)image_index;
    if (s_fail_next_boot_confirm) {
        s_fail_next_boot_confirm = false;
        return -EIO;
    }
    s_boot_upgrade_pending = false;
    return 0;
}

int boot_erase_img_bank(uint8_t area_id)
{
    (void)area_id;

    if (s_fail_next_boot_erase) {
        s_fail_next_boot_erase = false;
        return -EIO;
    }
    memset(s_slot_ram, 0xFF, sizeof(s_slot_ram));
    return 0;
}

int boot_read_bank_header(uint8_t area_id, struct mcuboot_img_header *header, size_t header_size)
{
    (void)area_id;

    if (header == NULL || header_size < sizeof(*header)) {
        return -EINVAL;
    }
    if (s_fail_next_boot_header) {
        s_fail_next_boot_header = false;
        return -EIO;
    }

    (void)memset(header, 0, sizeof(*header));
    header->mcuboot_version = 1U;
    return 0;
}
