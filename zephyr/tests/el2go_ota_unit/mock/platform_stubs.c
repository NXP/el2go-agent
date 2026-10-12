/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include <zephyr/device.h>

#include <psa/error.h>

#include "common/el2go_platform.h"
#include "common/el2go_status.h"
#include "plat_crypto_params.h"

/*
 * device_is_ready() dereferences dev->state, so a non-NULL device_state is 
 * required even though the real flash/NVS subsystem is stubbed out below.
 */
static struct device_state s_mock_flash_device_state;

const struct device __device_dts_ord_29 = {
    .name = "mock-flash",
    .state = &s_mock_flash_device_state,
};

struct nvs_fs;

int nvs_mount(struct nvs_fs *fs)
{
    (void)fs;
    return -1;
}

ssize_t nvs_write(struct nvs_fs *fs, uint16_t id, const void *data, size_t len)
{
    (void)fs;
    (void)id;
    (void)data;
    (void)len;
    return -1;
}

int nvs_delete(struct nvs_fs *fs, uint16_t id)
{
    (void)fs;
    (void)id;
    return -1;
}

ssize_t nvs_read(struct nvs_fs *fs, uint16_t id, void *data, size_t len)
{
    (void)fs;
    (void)id;
    (void)data;
    (void)len;
    return -1;
}

struct flash_pages_info;

int z_impl_flash_get_page_info_by_offs(const struct device *dev, off_t offset,
                                       struct flash_pages_info *info)
{
    (void)dev;
    (void)offset;
    (void)info;
    return -1;
}

struct psa_storage_info_t;

psa_status_t secure_storage_its_get(uint32_t caller_id, uint64_t uid, size_t data_offset,
                                    size_t data_size, void *p_data, size_t *p_data_length)
{
    (void)caller_id;
    (void)uid;
    (void)data_offset;
    (void)data_size;
    (void)p_data;
    (void)p_data_length;
    return PSA_ERROR_DOES_NOT_EXIST;
}

psa_status_t secure_storage_its_get_info(uint32_t caller_id, uint64_t uid,
                                         struct psa_storage_info_t *p_info)
{
    (void)caller_id;
    (void)uid;
    (void)p_info;
    return PSA_ERROR_DOES_NOT_EXIST;
}

struct el2go_platform_ctx {
    int dummy;
};

static struct el2go_platform_ctx g_mock_platform_ctx;

el2go_status_t el2go_platform_init(el2go_platform_ctx_t **platform_ctx)
{
    if (platform_ctx != NULL) {
        *platform_ctx = &g_mock_platform_ctx;
    }
    return EL2GO_STATUS_SUCCESS;
}

el2go_status_t el2go_platform_free(el2go_platform_ctx_t **platform_ctx)
{
    (void)platform_ctx;
    return EL2GO_STATUS_SUCCESS;
}

el2go_status_t el2go_platform_get_uuid(el2go_platform_ctx_t *platform_ctx, uint8_t *buf,
                                       size_t buf_len, size_t *uuid_len)
{
    (void)platform_ctx;
    (void)buf;
    (void)buf_len;
    (void)uuid_len;
    return EL2GO_STATUS_SUCCESS;
}

el2go_cipher_list_t el2go_platform_get_cipher_suites(void)
{
    el2go_cipher_list_t empty = { NULL, 0U };
    return empty;
}

el2go_curve_list_t el2go_platform_get_curves(void)
{
    el2go_curve_list_t empty = { NULL, 0U };
    return empty;
}
