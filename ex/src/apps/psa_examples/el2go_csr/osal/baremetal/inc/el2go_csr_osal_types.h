
/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef EL2GO_CSR_OSAL_TYPES_H
#define EL2GO_CSR_OSAL_TYPES_H

#include "app.h"
#include "board.h"
#include "fsl_debug_console.h"

#define scanc(fmt_s, ...)  SCANF(fmt_s, ##__VA_ARGS__)
#define printc(fmt_s, ...) PRINTF(fmt_s, ##__VA_ARGS__)

#endif // EL2GO_CSR_OSAL_TYPES_H
