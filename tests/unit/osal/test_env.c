/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <stddef.h>
#include "compiler.h"

#include "test_osal.h"

__weak const char *test_osal_getenv(const char *name)
{
    (void)name;

    return NULL;
}