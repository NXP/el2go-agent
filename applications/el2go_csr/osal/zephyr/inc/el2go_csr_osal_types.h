/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef EL2GO_CSR_OSAL_TYPES_H
#define EL2GO_CSR_OSAL_TYPES_H

#include <stdint.h>
#include <zephyr/sys/printk.h>

/* Map console output to Zephyr printk; scanf is not available on Zephyr. */
#define scanc(fmt_s, ...)              \
    do { /* not supported on Zephyr */ \
    } while (0)
#define printc(fmt_s, ...) printk(fmt_s, ##__VA_ARGS__)

#endif /* EL2GO_CSR_OSAL_TYPES_H */
