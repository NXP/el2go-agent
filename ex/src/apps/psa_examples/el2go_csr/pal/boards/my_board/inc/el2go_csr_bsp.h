/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef EL2GO_CSR_BSP_H
#define EL2GO_CSR_BSP_H

/*
 * Include board-specific headers required for hardware initialization
 * and stdout/UART communication support.
 */

/* Wrap your board-specific printf and scanf implementations in the macros below. */
#include <stdio.h>
#define SCANF(fmt_s, ...)  scanf(fmt_s, ##__VA_ARGS__)
#define PRINTF(fmt_s, ...) printf(fmt_s, ##__VA_ARGS__)

#endif // EL2GO_CSR_BSP_H
