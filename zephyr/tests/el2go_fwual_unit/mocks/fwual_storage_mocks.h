/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef EL2GO_FWUAL_STORAGE_MOCKS_H
#define EL2GO_FWUAL_STORAGE_MOCKS_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

/** Reset all fake state to a clean, unfaulted starting point. */
void fwual_fake_reset(void);

/** Override the write-block alignment reported by flash_area_align(). */
void fwual_fake_set_align(uint32_t align);

/** Force the next flash_area_erase() to fail with -EIO. */
void fwual_fake_fail_next_erase(bool arm);

/** Force the next flash_area_write() to fail with -EIO. */
void fwual_fake_fail_next_write(bool arm);

/** Force the next nvs_write() to fail with -EIO. */
void fwual_fake_fail_next_nvs_write(bool arm);

/** Force the next boot_erase_img_bank() to fail with -EIO. */
void fwual_fake_fail_next_boot_erase(bool arm);

/** Force the next nvs_write() of key @p id to fail with -EIO (other keys unaffected). */
void fwual_fake_fail_next_nvs_write_key(uint16_t id);

/** Force the next nvs_read() of key @p id to fail with -EIO (other keys unaffected). */
void fwual_fake_fail_next_nvs_read_key(uint16_t id);

/** Make the next nvs_write() store the value but report a short length (len - 1). */
void fwual_fake_short_next_nvs_write(bool arm);

/** Force every nvs_mount() to fail with -EIO until disarmed or reset. */
void fwual_fake_fail_nvs_mount(bool arm);

/** Force the next flash_area_open() to fail with -EIO. */
void fwual_fake_fail_next_open(bool arm);

/** Force the next flash_area_read() to fail with -EIO. */
void fwual_fake_fail_next_read(bool arm);

/** Force the next boot_request_upgrade_multi() to fail with -EIO. */
void fwual_fake_fail_next_boot_request(bool arm);

/** Force the next boot_write_img_confirmed_multi() to fail with -EIO. */
void fwual_fake_fail_next_boot_confirm(bool arm);

/** Force the next boot_read_bank_header() to fail with -EIO. */
void fwual_fake_fail_next_boot_header(bool arm);

/**
 * Pre-load NVS key @p id with @p len bytes of @p data, as if persisted by a
 * previous boot. Does not go through the nvs_write() fault knobs.
 *
 * @return false if @p id or @p len is out of range.
 */
bool fwual_fake_nvs_seed(uint16_t id, const void *data, size_t len);

/**
 * @return true if any one-shot fault is still armed, i.e. it was never consumed
 *         by the code under test. The sticky nvs_mount fault is not counted.
 */
bool fwual_fake_fault_pending(void);

/** @return true if a boot upgrade request is pending. */
bool fwual_fake_boot_pending(void);

/** @return read-only pointer to the fake secondary slot's RAM buffer. */
const uint8_t *fwual_fake_slot_data(size_t *out_size);

#endif /* EL2GO_FWUAL_STORAGE_MOCKS_H */
