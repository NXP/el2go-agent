/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <stdlib.h>

#include "osal.h"

void *osal_malloc(size_t size)
{
    return malloc(size);
}

void *osal_calloc(size_t nmemb, size_t size)
{
    return calloc(nmemb, size);
}

void osal_free(void *ptr)
{
    free(ptr);
}
