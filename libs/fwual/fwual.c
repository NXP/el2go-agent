/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "fwual/fwual.h"
#include "common/el2go_version.h"
#include "compiler.h"
#include "debug.h"

__weak __export fwual_result_t fwual_init(void)
{
    return FWUAL_ERR_INTERNAL;
}

__weak __export fwual_result_t fwual_get_caps(fwual_caps_t *out_caps)
{
    (void)out_caps;
    return FWUAL_ERR_INTERNAL;
}

__weak __export fwual_result_t fwual_open_session(fwual_session_t **out_session)
{
    (void)out_session;
    return FWUAL_ERR_INTERNAL;
}

__weak __export fwual_result_t fwual_close_session(fwual_session_t *session)
{
    (void)session;
    return FWUAL_ERR_INTERNAL;
}

__weak __export fwual_result_t fwual_prepare_image(fwual_session_t *session,
                                                   const fwual_image_desc_t *desc)
{
    (void)session;
    (void)desc;
    return FWUAL_ERR_INTERNAL;
}

__weak __export fwual_result_t fwual_cancel_image(fwual_session_t *session,
                                                  fwual_image_id_t image_id)
{
    (void)session;
    (void)image_id;
    return FWUAL_ERR_INTERNAL;
}

__weak __export fwual_result_t fwual_check_storage(fwual_session_t *session,
                                                   fwual_image_id_t image_id)
{
    (void)session;
    (void)image_id;
    return FWUAL_ERR_INTERNAL;
}

__weak __export fwual_result_t fwual_write(fwual_session_t *session, fwual_image_id_t image_id,
                                           uint64_t offset, const uint8_t *data, size_t len)
{
    (void)session;
    (void)image_id;
    (void)offset;
    (void)data;
    (void)len;
    return FWUAL_ERR_INTERNAL;
}

__weak __export fwual_result_t fwual_finalize_image(fwual_session_t *session,
                                                    fwual_image_id_t image_id)
{
    (void)session;
    (void)image_id;
    return FWUAL_ERR_INTERNAL;
}

__weak __export fwual_result_t fwual_verify_image(fwual_session_t *session,
                                                  fwual_image_id_t image_id)
{
    (void)session;
    (void)image_id;
    return FWUAL_ERR_INTERNAL;
}

__weak __export fwual_result_t fwual_commit_session(fwual_session_t *session)
{
    (void)session;
    return FWUAL_ERR_INTERNAL;
}

__weak __export fwual_result_t fwual_activate(void)
{
    return FWUAL_ERR_INTERNAL;
}

__weak __export fwual_result_t fwual_confirm(void)
{
    return FWUAL_ERR_INTERNAL;
}

__weak __export fwual_result_t fwual_rollback(void)
{
    return FWUAL_ERR_INTERNAL;
}

__weak __export fwual_state_t fwual_get_state(void)
{
    return FWUAL_STATE_FAILED;
}

__weak __export fwual_result_t fwual_list_installed(fwual_installed_image_t *list,
                                                    size_t *in_out_count)
{
    (void)list;
    (void)in_out_count;
    return FWUAL_ERR_INTERNAL;
}

__weak __export bool fwual_is_image_staged(fwual_session_t *session, fwual_image_id_t image_id)
{
    (void)session;
    (void)image_id;
    return false;
}

__export fwual_result_t fwual_get_version(unsigned int *major, unsigned int *minor,
                                          unsigned int *patch)
{
    fwual_result_t status = FWUAL_ERR_INVALID_PARAM;

    EL2GO_DBG_TRACE_API_CALL;

    if (major == NULL || minor == NULL || patch == NULL)
        goto exit;

    *major = EL2GO_LIB_VERSION_MAJOR;
    *minor = EL2GO_LIB_VERSION_MINOR;
    *patch = EL2GO_LIB_VERSION_PATCH;

    status = FWUAL_OK;

exit:
    EL2GO_DBG_PRINTF(VERBOSE, "%s returned %d\n", __func__, status);
    return status;
}
