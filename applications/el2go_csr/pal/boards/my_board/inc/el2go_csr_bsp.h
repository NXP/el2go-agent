/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef __EL2GO_CSR_BSP_H__
#define __EL2GO_CSR_BSP_H__

/*
 * Include board-specific headers required for hardware initialization
 * and stdout/UART communication support.
 */

/* Wrap your board-specific printf and scanf implementations in the macros below. */
#include <stdio.h>
#define SCANF(fmt_s, ...) scanf(fmt_s, ##__VA_ARGS__)
#define PRINTF(fmt_s, ...) printf(fmt_s, ##__VA_ARGS__)

#endif /* __EL2GO_CSR_BSP_H__ */
