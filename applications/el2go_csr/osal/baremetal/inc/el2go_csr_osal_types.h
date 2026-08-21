
/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef __EL2GO_CSR_OSAL_TYPES_H__
#define __EL2GO_CSR_OSAL_TYPES_H__

#include "el2go_csr_bsp.h"

#define scanc(fmt_s, ...) SCANF(fmt_s, ##__VA_ARGS__)
#define printc(fmt_s, ...) PRINTF(fmt_s, ##__VA_ARGS__)

#endif /* __EL2GO_CSR_OSAL_TYPES_H__ */
