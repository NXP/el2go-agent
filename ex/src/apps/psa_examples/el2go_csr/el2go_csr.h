/*--------------------------------------------------------------------------*/
/* Copyright 2026 NXP                                                       */
/*                                                                          */
/* NXP Confidential and Proprietary. This software is owned or controlled   */
/* by NXP and may only be used strictly in accordance with the applicable   */
/* license terms. By expressly accepting such terms or by downloading,      */
/* installing, activating and/or otherwise using the software, you are      */
/* agreeing that you have read, and that you agree to comply with and are   */
/* bound by, such license terms. If you do not agree to be bound by the     */
/* applicable license terms, then you may not retain, install, activate     */
/* or otherwise use the software.                                           */
/*--------------------------------------------------------------------------*/
/** @file */
#ifndef _EL2GO_CSR_H_
#define _EL2GO_CSR_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "psa/crypto.h"
#include "el2go_csr_tlv_parser.h"

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