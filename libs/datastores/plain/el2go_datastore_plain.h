/*
 * Copyright 2018-2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef __EL2GO_DATASTORE_PLAIN_H__
#define __EL2GO_DATASTORE_PLAIN_H__

#include "common/el2go_datastore.h"

/**
 * el2go_datastore_plain_create - Create and initialize a plain memory datastore
 * @datastore: Pointer to datastore structure to initialize
 * @basename: Unused parameter (for signature consistency)
 *
 * This function initializes a plain memory-based datastore by setting up the
 * operation handlers and allocating the internal context.
 *
 * Return:
 * EL2GO_STATUS_SUCCESS on success, error code otherwise
 */
el2go_status_t el2go_datastore_plain_create(el2go_datastore_t *datastore, const char *basename);

#endif /* __EL2GO_DATASTORE_PLAIN_H__ */
