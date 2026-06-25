/*
 * Copyright 2018-2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>

#include "rtp/el2go_rtp.h"
#include "common/el2go_status.h"

#include "el2go_rtp_internal.h"
#include "compiler.h"
#include "osal.h"
#include "debug.h"

/**
 * get_datastore_index_by_id - Get datastore index by identifier
 * @ctx: RTP agent context
 * @id: Datastore identifier to search for
 * @index: Pointer to store the found index
 *
 * This function searches through the registered datastores in the agent context
 * to find a datastore with the specified identifier. If found, the index of the
 * datastore in the internal array is returned through the index parameter.
 *
 * Return:
 * EL2GO_STATUS_SUCCESS on success, error code otherwise
 */
static el2go_status_t get_datastore_index_by_id(const el2go_rtp_ctx_t *ctx, uint32_t id,
                                                size_t *index)
{
    el2go_status_t status = EL2GO_STATUS_INVALID_PARAMETER;
    size_t i = 0;

    EL2GO_DBG_TRACE_FUNCTION_CALL;

    if (!ctx || !index)
        goto exit;

    status = EL2GO_STATUS_NOT_FOUND;

    for (; i < ctx->num_datastores; i++) {
        if (ctx->datastores[i]->id == id) {
            *index = i;
            status = EL2GO_STATUS_SUCCESS;
            goto exit;
        }
    }

exit:
    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}

/**
 * get_keystore_index_by_id - Get keystore index by identifier
 * @ctx: RTP agent context
 * @id: Keystore identifier to search for
 * @index: Pointer to store the found index
 *
 * This function searches through the registered keystores in the agent context
 * to find a keystore with the specified identifier. If found, the index of the
 * keystore in the internal array is returned through the index parameter.
 *
 * Return:
 * EL2GO_STATUS_SUCCESS on success, error code otherwise
 */
static el2go_status_t get_keystore_index_by_id(const el2go_rtp_ctx_t *ctx, uint32_t id,
                                               size_t *index)
{
    el2go_status_t status = EL2GO_STATUS_INVALID_PARAMETER;
    size_t i = 0;

    EL2GO_DBG_TRACE_FUNCTION_CALL;

    if (!ctx || !index)
        goto exit;

    status = EL2GO_STATUS_NOT_FOUND;

    for (; i < ctx->num_keystores; i++) {
        if (ctx->keystores[i]->id == id) {
            *index = i;
            status = EL2GO_STATUS_SUCCESS;
            goto exit;
        }
    }

exit:
    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}

__export el2go_status_t el2go_rtp_get_version(unsigned int *major, unsigned int *minor)
{
    el2go_status_t status = EL2GO_STATUS_INVALID_PARAMETER;

    EL2GO_DBG_TRACE_API_CALL;

    if (!major || !minor)
        goto exit;

    *major = 0;
    *minor = 0;

    status = EL2GO_STATUS_SUCCESS;

exit:
    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}

__export el2go_status_t el2go_rtp_init(el2go_rtp_ctx_t **ctx)
{
    el2go_status_t status = EL2GO_STATUS_INVALID_PARAMETER;
    el2go_rtp_ctx_t *agent_ctx = NULL;

    if (!ctx)
        goto exit;

    /* Initialize OSAL subsystem */
    osal_lib_init();

    /* Allocate memory for RTP agent context */
    agent_ctx = (el2go_rtp_ctx_t *)osal_calloc(1, sizeof(el2go_rtp_ctx_t));
    if (!agent_ctx) {
        status = EL2GO_STATUS_ALLOCATION_ERROR;
        goto exit;
    }

    *ctx = agent_ctx;

    status = EL2GO_STATUS_SUCCESS;

exit:
    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}

__export el2go_status_t el2go_rtp_free(el2go_rtp_ctx_t **ctx)
{
    el2go_status_t status = EL2GO_STATUS_INVALID_PARAMETER;

    EL2GO_DBG_TRACE_API_CALL;

    if (!ctx || !*ctx)
        goto exit;

    /* Free the allocated context */
    osal_free(*ctx);
    *ctx = NULL;

    status = EL2GO_STATUS_SUCCESS;

exit:
    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}

__export el2go_status_t el2go_rtp_add_datastore(el2go_rtp_ctx_t *ctx, el2go_datastore_t *datastore)
{
    el2go_status_t status = EL2GO_STATUS_INVALID_PARAMETER;
    size_t index = 0;

    EL2GO_DBG_TRACE_API_CALL;

    if (!ctx || !datastore)
        goto exit;

    if (ctx->num_datastores >= EL2GO_RTP_MAX_DATASTORES) {
        EL2GO_DBG_PRINTF(ERROR, "Unable to register datastore, maximum number reached\n");
        status = EL2GO_STATUS_RESOURCE_LIMIT;
        goto exit;
    }

    /* Check for identifier uniqueness against existing datastores */
    status = get_datastore_index_by_id(ctx, datastore->id, &index);
    if (status == EL2GO_STATUS_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR,
                         "Unable to register datastore with id 0x%08" PRIx32
                         ", a datastore with that id is already registered\n",
                         datastore->id);
        status = EL2GO_STATUS_ALREADY_EXISTS;
        goto exit;
    }

    /* Check for identifier uniqueness against existing keystores */
    status = get_keystore_index_by_id(ctx, datastore->id, &index);
    if (status == EL2GO_STATUS_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR,
                         "Unable to register datastore with id 0x%08" PRIx32
                         ", a keystore with that id is already registered\n",
                         datastore->id);
        status = EL2GO_STATUS_ALREADY_EXISTS;
        goto exit;
    }

    /* Register the datastore */
    ctx->datastores[ctx->num_datastores] = datastore;
    ctx->num_datastores++;

    status = EL2GO_STATUS_SUCCESS;

exit:
    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}

__export el2go_status_t el2go_rtp_remove_datastore(el2go_rtp_ctx_t *ctx,
                                                   el2go_datastore_t *datastore)
{
    el2go_status_t status = EL2GO_STATUS_INVALID_PARAMETER;
    size_t index = 0;

    EL2GO_DBG_TRACE_API_CALL;

    if (!ctx || !datastore)
        goto exit;

    if (ctx->num_datastores == 0) {
        status = EL2GO_STATUS_INVALID_STATE;
        goto exit;
    }

    status = get_datastore_index_by_id(ctx, datastore->id, &index);
    if (status != EL2GO_STATUS_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "Datastore with id 0x%08" PRIx32 " not found\n", datastore->id);
        goto exit;
    }

    /*
	 * Shift remaining datastores to fill the gap.
	 * Note: Using a simple array with memmove is acceptable here since
	 * the number of datastores is expected to be low (limited by
	 * EL2GO_RTP_MAX_DATASTORES) and does not justify the overhead of
	 * a linked list implementation.
	 */
    if (index < ctx->num_datastores - 1)
        memmove(&ctx->datastores[index], &ctx->datastores[index + 1],
                (ctx->num_datastores - index - 1) * sizeof(el2go_datastore_t *));

    ctx->num_datastores--;
    ctx->datastores[ctx->num_datastores] = NULL;

    status = EL2GO_STATUS_SUCCESS;

exit:
    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}

__export el2go_status_t el2go_rtp_get_datastore_by_id(el2go_rtp_ctx_t *ctx, uint32_t id,
                                                      el2go_datastore_t **datastore)
{
    el2go_status_t status = EL2GO_STATUS_INVALID_PARAMETER;
    size_t index = 0;

    EL2GO_DBG_TRACE_API_CALL;

    if (!ctx || !datastore)
        goto exit;

    status = get_datastore_index_by_id(ctx, id, &index);
    if (status != EL2GO_STATUS_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "Datastore with id 0x%08" PRIx32 " not found\n", id);
        goto exit;
    }

    *datastore = ctx->datastores[index];

    status = EL2GO_STATUS_SUCCESS;

exit:
    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}

__export el2go_status_t el2go_rtp_provision(el2go_rtp_ctx_t *ctx, el2go_verbosity_t verbosity)
{
    el2go_status_t status = EL2GO_STATUS_INVALID_PARAMETER;

    EL2GO_DBG_TRACE_API_CALL;

    (void)verbosity;

    if (!ctx)
        goto exit;

    /* TODO: Connect to EdgeLock 2GO server */
    /* TODO: Provision keys and certificates */
    /* TODO: Populate status_report from server response */
    /* TODO: Set result based on provisioning outcome */

    status = EL2GO_STATUS_SUCCESS;

exit:
    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}

__export el2go_status_t el2go_rtp_add_keystore(el2go_rtp_ctx_t *ctx, el2go_keystore_t *keystore)
{
    el2go_status_t status = EL2GO_STATUS_INVALID_PARAMETER;
    size_t index = 0;

    EL2GO_DBG_TRACE_API_CALL;

    if (!ctx || !keystore)
        goto exit;

    if (ctx->num_keystores >= EL2GO_RTP_MAX_KEYSTORES) {
        EL2GO_DBG_PRINTF(ERROR, "Unable to register keystore, maximum number reached\n");
        status = EL2GO_STATUS_RESOURCE_LIMIT;
        goto exit;
    }

    /* Check for identifier uniqueness against existing keystores */
    status = get_keystore_index_by_id(ctx, keystore->id, &index);
    if (status == EL2GO_STATUS_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR,
                         "Unable to register keystore with id 0x%08" PRIx32
                         ", a keystore with that id is already registered\n",
                         keystore->id);
        status = EL2GO_STATUS_ALREADY_EXISTS;
        goto exit;
    }

    /* Check for identifier uniqueness against existing datastores */
    status = get_datastore_index_by_id(ctx, keystore->id, &index);
    if (status == EL2GO_STATUS_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR,
                         "Unable to register keystore with id 0x%08" PRIx32
                         ", a datastore with that id is already registered\n",
                         keystore->id);
        status = EL2GO_STATUS_ALREADY_EXISTS;
        goto exit;
    }

    /* Register the keystore */
    ctx->keystores[ctx->num_keystores] = keystore;
    ctx->num_keystores++;

    status = EL2GO_STATUS_SUCCESS;

exit:
    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}

__export el2go_status_t el2go_rtp_remove_keystore(el2go_rtp_ctx_t *ctx, el2go_keystore_t *keystore)
{
    el2go_status_t status = EL2GO_STATUS_INVALID_PARAMETER;
    size_t index = 0;

    EL2GO_DBG_TRACE_API_CALL;

    if (!ctx || !keystore)
        goto exit;

    if (ctx->num_keystores == 0) {
        status = EL2GO_STATUS_INVALID_STATE;
        goto exit;
    }

    status = get_keystore_index_by_id(ctx, keystore->id, &index);
    if (status != EL2GO_STATUS_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "Keystore with id 0x%08" PRIx32 " not found\n", keystore->id);
        goto exit;
    }

    /*
     * Shift remaining keystores to fill the gap.
     * Note: Using a simple array with memmove is acceptable here since
     * the number of keystores is expected to be low (limited by
     * EL2GO_RTP_MAX_KEYSTORES) and does not justify the overhead of
     * a linked list implementation.
     */
    if (index < ctx->num_keystores - 1)
        memmove(&ctx->keystores[index], &ctx->keystores[index + 1],
                (ctx->num_keystores - index - 1) * sizeof(el2go_keystore_t *));

    ctx->num_keystores--;
    ctx->keystores[ctx->num_keystores] = NULL;

    status = EL2GO_STATUS_SUCCESS;

exit:
    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}

__export el2go_status_t el2go_rtp_get_keystore_by_id(el2go_rtp_ctx_t *ctx, uint32_t id,
                                                     el2go_keystore_t **keystore)
{
    el2go_status_t status = EL2GO_STATUS_INVALID_PARAMETER;
    size_t index = 0;

    EL2GO_DBG_TRACE_API_CALL;

    if (!ctx || !keystore)
        goto exit;

    status = get_keystore_index_by_id(ctx, id, &index);
    if (status != EL2GO_STATUS_SUCCESS) {
        EL2GO_DBG_PRINTF(ERROR, "Keystore with id 0x%08" PRIx32 " not found\n", id);
        goto exit;
    }

    *keystore = ctx->keystores[index];

    status = EL2GO_STATUS_SUCCESS;

exit:
    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}

__export el2go_status_t el2go_rtp_get_device_uuid(el2go_rtp_ctx_t *ctx, char *uuid_buffer,
                                                  size_t *buffer_size)
{
    el2go_status_t status = EL2GO_STATUS_INVALID_PARAMETER;

    EL2GO_DBG_TRACE_API_CALL;

    if (!ctx || !uuid_buffer || !buffer_size)
        goto exit;

    status = EL2GO_STATUS_SUCCESS;

exit:
    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}

__export el2go_status_t el2go_rtp_datastore_el2go(el2go_datastore_t *datastore,
                                                  el2go_keystore_t *keystore_ctx,
                                                  const el2go_rtp_datastore_config_t *config)
{
    el2go_status_t status = EL2GO_STATUS_INVALID_PARAMETER;

    EL2GO_DBG_TRACE_API_CALL;

    if (!datastore || !keystore_ctx || !config)
        goto exit;

    /* TODO: Implement EdgeLock 2GO configuration */

    status = EL2GO_STATUS_SUCCESS;

exit:
    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}
