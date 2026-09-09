/*
 * Copyright 2018-2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef __EL2GO_DATASTORE_FS_H__
#define __EL2GO_DATASTORE_FS_H__

#include "common/el2go_datastore.h"

/**
 * @defgroup el2go_datastore_fs Filesystem Datastore
 * @brief Filesystem-backed datastore implementation for EdgeLock 2GO.
 * @{
 */

/**
 * @brief Create and initialize a filesystem datastore.
 *
 * Initializes a filesystem-based datastore by setting up the operation
 * handlers and allocating the internal context. The basename parameter
 * specifies the directory path where datastore files will be stored.
 *
 * @param[out] datastore Pointer to datastore structure to initialize
 * @param[in]  basename  Base path for datastore files
 *
 * @return EL2GO_STATUS_SUCCESS on success, error code otherwise
 */
el2go_status_t el2go_datastore_fs_create(el2go_datastore_t *datastore, const char *basename);

/** @} */ /* end of el2go_datastore_fs */

#endif /* __EL2GO_DATASTORE_FS_H__ */
