/*
 * Copyright 2018-2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <stddef.h>

#include "compiler.h"
#include "debug.h"
#include "builtin_macros.h"

#include "common/el2go_datastore.h"
#include "el2go_datastore_plain.h"
#include "el2go_datastore_fs.h"

typedef el2go_status_t (*datastore_create_fn_t)(el2go_datastore_t *datastore, const char *basename);

static const datastore_create_fn_t datastore_create_functions[] = {
    [EL2GO_DATASTORE_TYPE_FS] = el2go_datastore_fs_create,
    [EL2GO_DATASTORE_TYPE_PLAIN] = el2go_datastore_plain_create,
    [EL2GO_DATASTORE_TYPE_CUSTOM] = NULL,
};

__export el2go_status_t el2go_datastore_init(uint32_t id, const char *name,
                                             el2go_datastore_type_t type,
                                             el2go_datastore_t *datastore,
                                             el2go_datastore_validator_t validator)
{
    el2go_status_t status = EL2GO_STATUS_SUCCESS;

    EL2GO_DBG_TRACE_FUNCTION_CALL;

    if (!datastore) {
        status = EL2GO_STATUS_INVALID_PARAMETER;
        goto exit;
    }

    datastore->id = id;
    datastore->name = name;
    datastore->type = type;
    datastore->priv = NULL;

    if (type >= ARRAY_SIZE(datastore_create_functions)) {
        status = EL2GO_STATUS_INVALID_PARAMETER;
        goto cleanup;
    }

    if (datastore_create_functions[type]) {
        status = datastore_create_functions[type](datastore, name);
        if (status != EL2GO_STATUS_SUCCESS)
            goto exit;
    }

    if (!datastore->ops || !datastore->ops->init) {
        status = EL2GO_STATUS_INVALID_POINTER;
        goto cleanup;
    }

    status = datastore->ops->init(datastore->context, validator);
    if (status == EL2GO_STATUS_SUCCESS)
        goto exit;

cleanup:
    (void)el2go_datastore_free(datastore);

exit:
    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}

__export el2go_status_t el2go_datastore_allocate(el2go_datastore_t *datastore, size_t len)
{
    el2go_status_t status = EL2GO_STATUS_SUCCESS;

    EL2GO_DBG_TRACE_FUNCTION_CALL;

    if (len == 0 || !datastore || !datastore->ops || !datastore->ops->allocate) {
        status = EL2GO_STATUS_INVALID_PARAMETER;
        goto exit;
    }

    status = datastore->ops->allocate(datastore->context, len);

exit:
    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}

__export el2go_status_t el2go_datastore_read(el2go_datastore_t *datastore, void *dest,
                                             size_t offset, size_t len, size_t *bytes_read)
{
    el2go_status_t status = EL2GO_STATUS_SUCCESS;

    EL2GO_DBG_TRACE_FUNCTION_CALL;

    if (len == 0 || !dest || !datastore || !datastore->ops || !datastore->ops->read ||
        !bytes_read) {
        status = EL2GO_STATUS_INVALID_PARAMETER;
        goto exit;
    }

    *bytes_read = 0;

    status = datastore->ops->read(datastore->context, dest, offset, len, bytes_read);

exit:
    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}

__export el2go_status_t el2go_datastore_write(el2go_datastore_t *datastore, const void *src,
                                              size_t offset, size_t len, size_t *bytes_written)
{
    el2go_status_t status = EL2GO_STATUS_SUCCESS;

    EL2GO_DBG_TRACE_FUNCTION_CALL;

    if (len == 0 || !src || !datastore || !datastore->ops || !datastore->ops->write ||
        !bytes_written) {
        status = EL2GO_STATUS_INVALID_PARAMETER;
        goto exit;
    }

    *bytes_written = 0;

    status = datastore->ops->write(datastore->context, src, offset, len, bytes_written);

exit:
    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}

__export el2go_status_t el2go_datastore_commit(el2go_datastore_t *datastore)
{
    el2go_status_t status = EL2GO_STATUS_SUCCESS;

    EL2GO_DBG_TRACE_FUNCTION_CALL;

    if (!datastore || !datastore->ops || !datastore->ops->commit) {
        status = EL2GO_STATUS_INVALID_PARAMETER;
        goto exit;
    }

    status = datastore->ops->commit(datastore->context);

exit:
    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}

__export el2go_status_t el2go_datastore_free(el2go_datastore_t *datastore)
{
    el2go_status_t status = EL2GO_STATUS_SUCCESS;

    EL2GO_DBG_TRACE_FUNCTION_CALL;

    if (!datastore) {
        status = EL2GO_STATUS_INVALID_PARAMETER;
        goto exit;
    }

    if (datastore->context && datastore->ops && datastore->ops->free)
        status = datastore->ops->free(datastore->context);

    datastore->context = NULL;
    datastore->ops = NULL;

exit:
    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}
