/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef __EL2GO_IMPORT_BLOB_OSAL_TYPES_H__
#define __EL2GO_IMPORT_BLOB_OSAL_TYPES_H__

#include <stdint.h>
#include <zephyr/sys/printk.h>

/* Map console output to Zephyr printk. */
#define printc(fmt_s, ...) printk(fmt_s, ##__VA_ARGS__)

#endif /* __EL2GO_IMPORT_BLOB_OSAL_TYPES_H__ */
