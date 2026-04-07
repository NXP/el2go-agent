/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef EL2GO_CSR_OSAL_TYPES_H
#define EL2GO_CSR_OSAL_TYPES_H

#include <stdint.h>
#include <stdio.h>

#define scanc(fmt_s, ...)   scanf(fmt_s, ##__VA_ARGS__)
#define printc(fmt_s, ...)  printf(fmt_s, ##__VA_ARGS__)

#endif // EL2GO_CSR_OSAL_TYPES_H
