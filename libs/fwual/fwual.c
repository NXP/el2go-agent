/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "fwual/fwual.h"
#include "compiler.h"

__export fwual_result_t fwual_init(void)
{
    /* stub - not yet implemented */
    return FWUAL_ERR_INTERNAL;
}

__export fwual_result_t fwual_get_caps(fwual_caps_t *out_caps)
{
    /* stub - not yet implemented */
    (void)out_caps;

    return FWUAL_ERR_INTERNAL;
}

__export fwual_result_t fwual_open_session(fwual_session_t **out_session)
{
    /* stub - not yet implemented */
    (void)out_session;

    return FWUAL_ERR_INTERNAL;
}

__export fwual_result_t fwual_close_session(fwual_session_t *session)
{
    /* stub - not yet implemented */
    (void)session;

    return FWUAL_ERR_INTERNAL;
}

__export fwual_result_t fwual_prepare_image(fwual_session_t *session,
                                            const fwual_image_desc_t *desc)
{
    /* stub - not yet implemented */
    (void)session;
    (void)desc;

    return FWUAL_ERR_INTERNAL;
}

__export fwual_result_t fwual_check_storage(fwual_session_t *session, fwual_image_id_t image_id)
{
    /* stub - not yet implemented */
    (void)session;
    (void)image_id;

    return FWUAL_ERR_INTERNAL;
}

__export fwual_result_t fwual_cancel_image(fwual_session_t *session, fwual_image_id_t image_id)
{
    /* stub - not yet implemented */
    (void)session;
    (void)image_id;

    return FWUAL_ERR_INTERNAL;
}

__export fwual_result_t fwual_write(fwual_session_t *session, fwual_image_id_t image_id,
                                    uint64_t offset, const uint8_t *data, size_t len)
{
    /* stub - not yet implemented */
    (void)session;
    (void)image_id;
    (void)offset;
    (void)data;
    (void)len;

    return FWUAL_ERR_INTERNAL;
}

__export fwual_result_t fwual_finalize_image(fwual_session_t *session, fwual_image_id_t image_id)
{
    /* stub - not yet implemented */
    (void)session;
    (void)image_id;

    return FWUAL_ERR_INTERNAL;
}

__export fwual_result_t fwual_verify_image(fwual_session_t *session, fwual_image_id_t image_id)
{
    /* stub - not yet implemented */
    (void)session;
    (void)image_id;

    return FWUAL_ERR_INTERNAL;
}

__export fwual_result_t fwual_commit_session(fwual_session_t *session)
{
    /* stub - not yet implemented */
    (void)session;

    return FWUAL_ERR_INTERNAL;
}

__export fwual_result_t fwual_activate(void)
{
    /* stub - not yet implemented */
    return FWUAL_ERR_INTERNAL;
}

__export fwual_result_t fwual_confirm(void)
{
    /* stub - not yet implemented */
    return FWUAL_ERR_INTERNAL;
}

__export fwual_result_t fwual_rollback(void)
{
    /* stub - not yet implemented */
    return FWUAL_ERR_INTERNAL;
}

__export fwual_state_t fwual_get_state(void)
{
    /* stub - not yet implemented */
    return FWUAL_STATE_FAILED;
}

__export fwual_result_t fwual_list_installed(fwual_installed_image_t *list, size_t *in_out_count)
{
    /* stub - not yet implemented */
    (void)list;
    (void)in_out_count;

    return FWUAL_ERR_INTERNAL;
}

__export bool fwual_is_image_staged(fwual_session_t *session, fwual_image_id_t image_id)
{
    /* stub - not yet implemented */
    (void)session;
    (void)image_id;

    return false;
}
