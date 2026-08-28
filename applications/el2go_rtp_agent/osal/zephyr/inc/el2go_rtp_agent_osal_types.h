/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __EL2GO_RTP_AGENT_OSAL_TYPES_H__
#define __EL2GO_RTP_AGENT_OSAL_TYPES_H__

#include <zephyr/sys/printk.h>

/* Map console output to Zephyr printk. */
#define printc(fmt, ...) printk(fmt, ##__VA_ARGS__)

#endif /* __EL2GO_RTP_AGENT_OSAL_TYPES_H__ */
