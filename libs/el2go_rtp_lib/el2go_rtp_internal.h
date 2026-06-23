/*
 * Copyright 2018-2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef __EL2GO_INTERNAL_H__
#define __EL2GO_INTERNAL_H__

#include "rtp/el2go_rtp.h"
#include "common/el2go_keystore.h"
#include "common/el2go_datastore.h"
#include "rtp/el2go_rtp_config.h"

/* Agent context structure */
struct el2go_rtp_ctx {
    el2go_keystore_t *keystores[EL2GO_RTP_MAX_KEYSTORES];    /* Array of keystore pointers */
    el2go_datastore_t *datastores[EL2GO_RTP_MAX_DATASTORES]; /* Array of datastore pointers */
    size_t num_keystores;                                    /* Number of active keystores */
    size_t num_datastores;                                   /* Number of active datastores */
};

#endif /* __EL2GO_INTERNAL_H__ */
