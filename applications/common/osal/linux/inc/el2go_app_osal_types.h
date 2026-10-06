/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __EL2GO_APP_OSAL_TYPES_H__
#define __EL2GO_APP_OSAL_TYPES_H__

#include <stdio.h>

/* Map shared application console output to standard printf. */
#define EL2GO_APP_PRINTC(fmt, ...) printf(fmt, ##__VA_ARGS__)

#endif /* __EL2GO_APP_OSAL_TYPES_H__ */
