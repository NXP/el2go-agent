/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <stdlib.h>

const char *test_osal_getenv(const char *name)
{
    if (!name)
        return NULL;

    return getenv(name);
}