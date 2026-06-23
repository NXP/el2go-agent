/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <stdlib.h>
#include "common/el2go_status.h"
#include "osal.h"

struct osal_file {
    /* unused on Zephyr */
    int dummy;
};

osal_file_t *osal_fopen(const char *filename, const char *mode)
{
    (void)filename;
    (void)mode;
    return NULL;
}

el2go_status_t osal_fclose(osal_file_t *file)
{
    (void)file;
    return EL2GO_STATUS_NOT_IMPLEMENTED;
}

size_t osal_fread(void *ptr, size_t size, size_t nmemb, osal_file_t *file)
{
    (void)ptr;
    (void)size;
    (void)nmemb;
    (void)file;
    return 0;
}

size_t osal_fwrite(const void *ptr, size_t size, size_t nmemb, osal_file_t *file)
{
    (void)ptr;
    (void)size;
    (void)nmemb;
    (void)file;
    return 0;
}

el2go_status_t osal_fseek(osal_file_t *file, long offset, osal_seek_origin_t origin)
{
    (void)file;
    (void)offset;
    (void)origin;
    return EL2GO_STATUS_NOT_IMPLEMENTED;
}

long osal_ftell(osal_file_t *file)
{
    (void)file;
    return -1;
}

el2go_status_t osal_fflush(osal_file_t *file)
{
    (void)file;
    return EL2GO_STATUS_NOT_IMPLEMENTED;
}
