/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright 2018-2026 NXP
 */

#ifndef __EL2GO_INTERNAL_H__
#define __EL2GO_INTERNAL_H__

#include "rtp/el2go_rtp.h"
#include "common/el2go_keystore.h"
#include "common/el2go_datastore.h"
#include "rtp/el2go_rtp_config.h"

/* Agent context structure */
/* clang-format off */
struct el2go_agent_ctx {
	el2go_agent_keystore_t keystores[EL2GO_AGENT_MAX_KEYSTORES];        /* Array of keystores */
	el2go_agent_datastore_t datastores[EL2GO_AGENT_MAX_DATASTORES];     /* Array of datastores */
	size_t num_keystores;                                               /* Number of active keystores */
	size_t num_datastores;                                              /* Number of active datastores */
};

/* clang-format on */

#endif /* __EL2GO_INTERNAL_H__ */
