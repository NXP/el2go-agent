/*
 * Copyright 2018-2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef __EL2GO_DATASTORE_H__
#define __EL2GO_DATASTORE_H__

#include <stdint.h>
#include <stddef.h>

#include "common/el2go_status.h"

/**
 * @defgroup el2go_datastore Datastore Public API
 * @brief Datastore abstraction interface for EdgeLock 2GO.
 * @{
 */

/**
 * @brief Datastore types.
 */
typedef enum {
    EL2GO_DATASTORE_TYPE_FS,    /**< Filesystem-based datastore */
    EL2GO_DATASTORE_TYPE_PLAIN, /**< Plain memory datastore */
    EL2GO_DATASTORE_TYPE_CUSTOM /**< Custom user-provided datastore */
} el2go_datastore_type_t;

/**
 * @brief Chunk size in bytes used when streaming datastore read/write data.
 *
 * Data is transferred between the datastore and the protobuf stream in chunks
 * of this size. Increasing the value reduces loop iterations at the cost of
 * more stack space.
 */
#ifndef EL2GO_DATASTORE_CHUNK_SIZE
#define EL2GO_DATASTORE_CHUNK_SIZE 64U
#endif

/**
 * @brief Datastore used to persist non-secret data.
 *
 * See #el2go_datastore for the field documentation.
 */
typedef struct el2go_datastore el2go_datastore_t;

/**
 * @brief Datastore validator function pointer type.
 *
 * A validator function is called to verify the integrity and validity of
 * datastore contents. The function should perform any necessary checks
 * (e.g., checksum verification, format validation). If no custom validator
 * is provided (NULL), a default implementation will be used.
 *
 * @param[in] datastore Datastore to validate
 *
 * @return EL2GO_STATUS_SUCCESS if validation passes, error code otherwise
 */
typedef el2go_status_t (*el2go_datastore_validator_t)(el2go_datastore_t *datastore);

/* Function pointer types for datastore operations */

/**
 * @brief Initialize the custom datastore.
 *
 * Called during datastore initialization to set up any custom datastore
 * resources (e.g., open files, establish connections, allocate buffers).
 *
 * @param[in] context   User-provided context pointer
 * @param[in] validator Validator function pointer (can be NULL)
 *
 * @return EL2GO_STATUS_SUCCESS on success, error code otherwise
 */
typedef el2go_status_t (*el2go_datastore_init_t)(void *context,
                                                 el2go_datastore_validator_t validator);

/**
 * @brief Allocate memory in the datastore.
 *
 * @param[in] context User-provided context pointer
 * @param[in] len     Number of bytes to allocate
 *
 * @return EL2GO_STATUS_SUCCESS on success, error code otherwise
 */
typedef el2go_status_t (*el2go_datastore_allocate_t)(void *context, size_t len);

/**
 * @brief Read data from the datastore.
 *
 * Attempts to read @p len bytes from the datastore at the specified offset.
 * The actual number of bytes read is returned in @p bytes_read.
 *
 * @param[in]  context    User-provided context pointer
 * @param[out] dest       Destination buffer
 * @param[in]  offset     Offset in the datastore to read from
 * @param[in]  len        Number of bytes to read
 * @param[out] bytes_read Actual number of bytes read
 *
 * @retval EL2GO_STATUS_SUCCESS if all requested bytes were read
 * @retval EL2GO_STATUS_INCOMPLETE_READ if fewer bytes were read
 * @retval el2go_status_t other error code on failure
 */
typedef el2go_status_t (*el2go_datastore_read_t)(void *context, void *dest, size_t offset,
                                                 size_t len, size_t *bytes_read);

/**
 * @brief Write data to the datastore.
 *
 * Attempts to write @p len bytes to the datastore at the specified offset.
 * The actual number of bytes written is returned in @p bytes_written.
 *
 * @param[in]  context       User-provided context pointer
 * @param[in]  src           Source buffer
 * @param[in]  offset        Offset in the datastore to write to
 * @param[in]  len           Number of bytes to write
 * @param[out] bytes_written Actual number of bytes written
 *
 * @retval EL2GO_STATUS_SUCCESS if all requested bytes were written
 * @retval EL2GO_STATUS_INCOMPLETE_WRITE if fewer bytes were written
 * @retval el2go_status_t other error code on failure
 */
typedef el2go_status_t (*el2go_datastore_write_t)(void *context, const void *src, size_t offset,
                                                  size_t len, size_t *bytes_written);

/**
 * @brief Commit pending changes to the datastore.
 *
 * @param[in] context User-provided context pointer
 *
 * @return EL2GO_STATUS_SUCCESS on success, error code otherwise
 */
typedef el2go_status_t (*el2go_datastore_commit_t)(void *context);

/**
 * @brief Get the number of bytes currently stored.
 *
 * @param[in]  context User-provided context pointer
 * @param[out] size    Number of bytes available for reading from the current
 *                     read slot (i.e. excluding the write-in-progress slot)
 *
 * @return EL2GO_STATUS_SUCCESS on success, error code otherwise
 */
typedef el2go_status_t (*el2go_datastore_get_size_t)(void *context, size_t *size);

/**
 * @brief Free datastore resources.
 *
 * Called during datastore cleanup to release any custom datastore resources.
 *
 * @param[in] context User-provided context pointer
 *
 * @return EL2GO_STATUS_SUCCESS on success, error code otherwise
 */
typedef el2go_status_t (*el2go_datastore_free_t)(void *context);

/**
 * @brief Datastore operations table.
 */
typedef struct el2go_datastore_ops {
    el2go_datastore_init_t init;         /**< Initialize the custom datastore */
    el2go_datastore_allocate_t allocate; /**< Allocate memory in datastore */
    el2go_datastore_read_t read;         /**< Read data from the datastore */
    el2go_datastore_write_t write;       /**< Write data to the datastore */
    el2go_datastore_commit_t commit;     /**< Commit pending changes */
    el2go_datastore_get_size_t get_size; /**< Get stored data size */
    el2go_datastore_free_t free;         /**< Free datastore resources */
} el2go_datastore_ops_t;

/**
 * @brief RTP Agent datastore.
 *
 * Contains fields used to manage datastores. Some fields are used by the
 * datastore implementations (context) and others manage the internal
 * implementation. Public fields include id, name, and type; the priv field
 * is for internal use only and must not be accessed or modified by users.
 */
struct el2go_datastore {
    uint32_t id;                      /**< Datastore identifier */
    char *name;                       /**< Datastore name */
    el2go_datastore_type_t type;      /**< Datastore type */
    const el2go_datastore_ops_t *ops; /**< Operations table (for custom type) */
    void *context;                    /**< Datastore context */
    void *priv;                       /**< Private data (do not access) */
};

/**
 * @brief Initialize a datastore.
 *
 * Initializes a datastore with the specified parameters. The validator
 * function can be provided for any datastore type (FS, PLAIN, or CUSTOM)
 * to perform custom validation of datastore contents.
 *
 * For CUSTOM type datastores, before calling this function the user must:
 * 1. Set datastore->ops to point to their el2go_datastore_ops_t structure
 * 2. Set datastore->context to their custom context (if needed)
 *
 * @param[in]  id        Datastore identifier
 * @param[in]  name      Datastore name
 * @param[in]  type      Datastore type (FS, PLAIN, or CUSTOM)
 * @param[out] datastore Pointer to the datastore structure to initialize
 * @param[in]  validator Validator function pointer (can be NULL for all types)
 *
 * @return EL2GO_STATUS_SUCCESS on success, error code otherwise
 */
el2go_status_t el2go_datastore_init(uint32_t id, const char *name, el2go_datastore_type_t type,
                                    el2go_datastore_t *datastore,
                                    el2go_datastore_validator_t validator);

/**
 * @brief Allocate memory in the datastore.
 *
 * Allocates @p len bytes in the datastore. The allocation behavior depends
 * on the datastore type (FS or PLAIN).
 *
 * @param[in] datastore Datastore
 * @param[in] len       Number of bytes to allocate
 *
 * @return EL2GO_STATUS_SUCCESS on success, error code otherwise
 */
el2go_status_t el2go_datastore_allocate(el2go_datastore_t *datastore, size_t len);

/**
 * @brief Read data from the datastore.
 *
 * Reads up to @p len bytes from the datastore at the specified offset into
 * the destination buffer. The actual number of bytes read is returned in
 * @p bytes_read.
 *
 * @param[in]  datastore  Datastore
 * @param[out] dest       Destination buffer
 * @param[in]  offset     Offset in the datastore to read from
 * @param[in]  len        Number of bytes to read
 * @param[out] bytes_read Actual number of bytes read
 *
 * @retval EL2GO_STATUS_SUCCESS if all requested bytes were read
 * @retval EL2GO_STATUS_INCOMPLETE_READ if fewer bytes were read
 * @retval el2go_status_t other error code on failure
 */
el2go_status_t el2go_datastore_read(el2go_datastore_t *datastore, void *dest, size_t offset,
                                    size_t len, size_t *bytes_read);

/**
 * @brief Write data to the datastore.
 *
 * Writes up to @p len bytes from the source buffer to the datastore at the
 * specified offset. The actual number of bytes written is returned in
 * @p bytes_written.
 *
 * @param[in]  datastore     Datastore
 * @param[in]  src           Source buffer
 * @param[in]  offset        Offset in the datastore to write to
 * @param[in]  len           Number of bytes to write
 * @param[out] bytes_written Actual number of bytes written
 *
 * @retval EL2GO_STATUS_SUCCESS if all requested bytes were written
 * @retval EL2GO_STATUS_INCOMPLETE_WRITE if fewer bytes were written
 * @retval el2go_status_t other error code on failure
 */
el2go_status_t el2go_datastore_write(el2go_datastore_t *datastore, const void *src, size_t offset,
                                     size_t len, size_t *bytes_written);

/**
 * @brief Commit a transaction to the datastore.
 *
 * Commits pending changes to the datastore.
 *
 * @param[in] datastore Datastore
 *
 * @return EL2GO_STATUS_SUCCESS on success, error code otherwise
 */
el2go_status_t el2go_datastore_commit(el2go_datastore_t *datastore);

/**
 * @brief Get the number of bytes available for reading.
 *
 * Returns the size of the data currently readable from the datastore.
 * For FS datastores this is the file size; for PLAIN datastores this is
 * the allocated buffer length. Does not read any data.
 *
 * @param[in]  datastore Datastore
 * @param[out] size      Number of bytes available from the current read slot
 *
 * @return EL2GO_STATUS_SUCCESS on success, error code otherwise
 */
el2go_status_t el2go_datastore_get_size(el2go_datastore_t *datastore, size_t *size);

/**
 * @brief Free a datastore.
 *
 * Frees all datastore resources and resets internal fields.
 *
 * @param[in] datastore Pointer to datastore (internal fields will be reset)
 *
 * @return EL2GO_STATUS_SUCCESS on success, error code otherwise
 */
el2go_status_t el2go_datastore_free(el2go_datastore_t *datastore);

/** @} */ /* end of el2go_datastore */

#endif /* __EL2GO_DATASTORE_H__ */
