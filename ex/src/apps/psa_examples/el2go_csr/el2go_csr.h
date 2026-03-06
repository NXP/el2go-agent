/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

/** @file */
#ifndef _EL2GO_CSR_H_
#define _EL2GO_CSR_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "psa/crypto.h"

#ifdef __ZEPHYR__
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#define LOG printf
#else
#include "app.h"
#include "fsl_debug_console.h"
#include "board.h"
#define LOG PRINTF
#endif



#ifdef __cplusplus
}
#endif

#endif /* _EL2GO_CSR_H_ */