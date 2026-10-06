/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __EL2GO_APP_LOG_H__
#define __EL2GO_APP_LOG_H__

#include "el2go_app_osal_types.h"

/* Info -- message only, no prefix. */
#define EL2GO_APP_LOG_INFO(fmt, ...)                 \
    do {                                             \
        EL2GO_APP_PRINTC(fmt "\r\n", ##__VA_ARGS__); \
    } while (0)

/* Warning -- includes WARN prefix, function name and line number. */
#define EL2GO_APP_LOG_WARN(fmt, ...)                                                         \
    do {                                                                                     \
        EL2GO_APP_PRINTC("WARN:    %s L#%d " fmt "\r\n", __func__, __LINE__, ##__VA_ARGS__); \
    } while (0)

/* Error -- includes ERROR prefix, function name and line number. */
#define EL2GO_APP_LOG_ERROR(fmt, ...)                                                        \
    do {                                                                                     \
        EL2GO_APP_PRINTC("ERROR:   %s L#%d " fmt "\r\n", __func__, __LINE__, ##__VA_ARGS__); \
    } while (0)

#endif /* __EL2GO_APP_LOG_H__ */
