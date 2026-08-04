/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef __EL2GO_IMPORT_BLOB_LOG_H__
#define __EL2GO_IMPORT_BLOB_LOG_H__

#include "el2go_import_blob_osal_types.h"

/*! @brief Log a formatted message to the console.
 *
 * Routes through printc which is mapped to the platform console output
 * (e.g. printk on Zephyr). No level filtering is applied at runtime;
 * all calls compile to a direct printc invocation.
 */
#define LOG(fmt, ...) printc(fmt, ##__VA_ARGS__)

#endif /* __EL2GO_IMPORT_BLOB_LOG_H__ */
