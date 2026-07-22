/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef __EL2GO_OTA_KVS_H__
#define __EL2GO_OTA_KVS_H__

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#include "ota/el2go_ota_lib.h"

el2go_ota_status_t el2go_ota_kvs_init(void);
el2go_ota_status_t el2go_ota_kvs_write(uint16_t key, const void *data, size_t len);
el2go_ota_status_t el2go_ota_kvs_read(uint16_t key, void *data, size_t len, bool *found);
el2go_ota_status_t el2go_ota_kvs_delete(uint16_t key);

#endif /* __EL2GO_OTA_KVS_H__ */
