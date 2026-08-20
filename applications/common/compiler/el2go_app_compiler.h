/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef __EL2GO_APP_COMPILER_H__
#define __EL2GO_APP_COMPILER_H__

#if defined(__ZEPHYR__) || defined(__GNUC__) || defined(__clang__)
#define __weak __attribute__((weak))
#else
#define __weak
#endif

#endif /* __EL2GO_APP_COMPILER_H__ */
