/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <errno.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <zephyr/storage/flash_map.h>

#include <zephyr/dfu/mcuboot.h>

static bool s_boot_upgrade_pending;

int boot_request_upgrade_multi(int image_index, int permanent)
{
    (void)image_index;
    (void)permanent;
    s_boot_upgrade_pending = true;
    return 0;
}

int boot_write_img_confirmed_multi(int image_index)
{
    (void)image_index;
    s_boot_upgrade_pending = false;
    return 0;
}

int boot_erase_img_bank(uint8_t area_id)
{
    const struct flash_area *fa = NULL;
    int rc = flash_area_open(area_id, &fa);

    if (rc != 0) {
        return rc;
    }
    rc = flash_area_erase(fa, 0, fa->fa_size);
    flash_area_close(fa);
    return rc;
}

int boot_read_bank_header(uint8_t area_id, struct mcuboot_img_header *header, size_t header_size)
{
    (void)area_id;

    if (header == NULL || header_size < sizeof(*header)) {
        return -EINVAL;
    }

    (void)memset(header, 0, sizeof(*header));
    header->mcuboot_version = 1U;
    return 0;
}

bool ct_fw_boot_pending_set(void)
{
    return s_boot_upgrade_pending;
}
