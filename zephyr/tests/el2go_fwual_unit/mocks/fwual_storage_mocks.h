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

/** @return true if a boot upgrade request is pending. */
bool fwual_fake_boot_pending(void);

/** @return read-only pointer to the fake secondary slot's RAM buffer. */
const uint8_t *fwual_fake_slot_data(size_t *out_size);

#endif /* EL2GO_FWUAL_STORAGE_MOCKS_H */
