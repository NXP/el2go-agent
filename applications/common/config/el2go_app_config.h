/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __EL2GO_APP_CONFIG_H__
#define __EL2GO_APP_CONFIG_H__

/** @brief Plain claimcode string to encrypt and write to flash.
 *
 * Can be overridden via Kconfig (CONFIG_EL2GO_CLAIMCODE_STRING) or by
 * defining EL2GO_CLAIMCODE_STRING before including this header.
 */
#ifndef EL2GO_CLAIMCODE_STRING
#ifdef CONFIG_EL2GO_CLAIMCODE_STRING
#define EL2GO_CLAIMCODE_STRING CONFIG_EL2GO_CLAIMCODE_STRING
#else
#define EL2GO_CLAIMCODE_STRING "insert_claimcode_from_el2go"
#endif
#endif

#endif /* __EL2GO_APP_CONFIG_H__ */
