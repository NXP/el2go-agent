/*
 * Copyright 2018-2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __EL2GO_AGENT_DATASTORE_H__
#define __EL2GO_AGENT_DATASTORE_H__

#include <stdint.h>
#include <stddef.h>
#include "el2go_agent_status.h"
#include "el2go_agent_keystore.h"

/*
 * Datastore types
 */
/* clang-format off */
typedef enum {
	EL2GO_AGENT_DATASTORE_TYPE_FS,      /* Filesystem-based datastore */
	EL2GO_AGENT_DATASTORE_TYPE_PLAIN,   /* Plain memory datastore */
	EL2GO_AGENT_DATASTORE_TYPE_CUSTOM   /* Custom user-provided datastore */
} el2go_agent_datastore_type_t;
/* clang-format on */

/*
 * Binary data buffer
 */
/* clang-format off */
typedef struct {
	const uint8_t *data;   /* Pointer to data */
	size_t len;            /* Length in bytes */
} el2go_agent_buffer_t;
/* clang-format on */

/* Function pointer types for datastore operations */

/**
 * el2go_agent_datastore_init_t - Initialize the custom datastore
 * @context: User-provided context pointer
 *
 * This is called during datastore initialization to set up any
 * custom datastore resources (e.g., open files, establish connections,
 * allocate buffers, etc.).
 *
 * Return: EL2GO_AGENT_SUCCESS on success, error code otherwise
 */
typedef el2go_agent_t (*el2go_agent_datastore_init_t)(void *context);

/**
 * el2go_agent_datastore_read_t - Read data from the datastore
 * @context: User-provided context pointer
 * @dest: Destination buffer
 * @offset: Offset in the datastore to read from
 * @len: Number of bytes to read
 *
 * Return: EL2GO_AGENT_SUCCESS on success, error code otherwise
 */
typedef el2go_agent_t (*el2go_agent_datastore_read_t)(void *context, void *dest,
						      size_t offset,
						      size_t len);

/**
 * el2go_agent_datastore_write_t - Write data to the datastore
 * @context: User-provided context pointer
 * @src: Source buffer
 * @offset: Offset in the datastore to write to
 * @len: Number of bytes to write
 *
 * Return: EL2GO_AGENT_SUCCESS on success, error code otherwise
 */
typedef el2go_agent_t (*el2go_agent_datastore_write_t)(void *context,
						       const void *src,
						       size_t offset,
						       size_t len);

/**
 * el2go_agent_datastore_commit_t - Commit pending changes to the datastore
 * @context: User-provided context pointer
 *
 * Return: EL2GO_AGENT_SUCCESS on success, error code otherwise
 */
typedef el2go_agent_t (*el2go_agent_datastore_commit_t)(void *context);

/**
 * el2go_agent_datastore_free_t - Free datastore resources
 * @context: User-provided context pointer
 *
 * This is called during datastore cleanup to release any custom
 * datastore resources.
 *
 * Return: EL2GO_AGENT_SUCCESS on success, error code otherwise
 */
typedef el2go_agent_t (*el2go_agent_datastore_free_t)(void *context);

/* clang-format off */
typedef struct el2go_agent_datastore_ops {
	el2go_agent_datastore_init_t init;      /* Initialize the custom datastore */
	el2go_agent_datastore_read_t read;      /* Read data from the datastore */
	el2go_agent_datastore_write_t write;    /* Write data to the datastore */
	el2go_agent_datastore_commit_t commit;  /* Commit pending changes */
	el2go_agent_datastore_free_t free;      /* Free datastore resources */
} el2go_agent_datastore_ops_t;
/* clang-format on */

/**
 * IoT Agent datastore
 *
 * This structure contains fields used to manage datastores. Some fields are
 * used by the datastore implementations (context) and others are used for
 * managing the datastores by the agent. Some of them are public fields
 * (like id, name, type) and some of them are private (priv).
 *
 * Users should only access and modify the public fields and the context field
 * for custom datastore implementations. The priv field is for internal agent
 * use only and must not be accessed or modified by users.
 */
/* clang-format off */
typedef struct el2go_agent_datastore {
	uint32_t id;                              /* Datastore identifier */
	const char *name;                         /* Datastore name */
	el2go_agent_datastore_type_t type;        /* Datastore type */
	const el2go_agent_datastore_ops_t *ops;   /* Operations (for custom type) */
	void *context;                            /* Data store context */
	void *priv;                               /* Private agent data (do not access) */
} el2go_agent_datastore_t;
/* clang-format on */

/**
 * Datastore validator function pointer type
 *
 * A validator function is called to verify the integrity and validity of
 * datastore contents.
 *
 * The validator function receives the datastore and should perform
 * any necessary checks on the datastore contents (e.g., checksum verification,
 * format validation, etc).
 *
 * If no custom validator is provided (NULL), the agent will use a default
 * implementation that performs basic validation checks.
 *
 * @datastore: Datastore to validate
 *
 * Return:
 * EL2GO_AGENT_SUCCESS if validation passes, error code otherwise
 */
typedef el2go_agent_t (*el2go_agent_datastore_validator_t)(
	el2go_agent_datastore_t *datastore);

/**
 * el2go_agent_datastore_init - Initialize a datastore
 * @id: Datastore identifier
 * @name: Datastore name
 * @type: Datastore type (FS, PLAIN, or CUSTOM)
 * @datastore: Pointer to store the created datastore
 * @validator: Validator function pointer (can be NULL for all types)
 *
 * This function initializes a datastore with the specified parameters.
 *
 * The validator function can be provided for any datastore type (FS, PLAIN,
 * or CUSTOM) to perform custom validation of datastore contents.
 *
 * For CUSTOM type datastores, before calling this function, the user must:
 * 1. Set datastore->ops to point to their el2go_agent_datastore_ops_t structure
 * 2. Set datastore->context to their custom context (if needed)
 *
 * This function will then call datastore->ops->init(datastore->context) to
 * initialize the custom datastore.
 *
 * Return:
 * EL2GO_AGENT_SUCCESS on success, error code otherwise
 */
el2go_agent_t
el2go_agent_datastore_init(uint32_t id, const char *name,
			   el2go_agent_datastore_type_t type,
			   el2go_agent_datastore_t *datastore,
			   el2go_agent_datastore_validator_t validator);

/**
 * el2go_agent_datastore_allocate - Allocate memory in the datastore
 * @datastore: Datastore
 * @len: Number of bytes to allocate
 *
 * Allocates len bytes in the datastore. The allocation behavior depends
 * on the datastore type (FS or PLAIN).
 *
 * Return:
 * Pointer to allocated memory on success, NULL on failure
 */
void *el2go_agent_datastore_allocate(el2go_agent_datastore_t *datastore,
				     size_t len);

/**
 * el2go_agent_datastore_read - Read data from the datastore
 * @datastore: Datastore
 * @dest: Destination buffer
 * @offset: Offset in the datastore to read from
 * @len: Number of bytes to read
 *
 * Reads len bytes from the datastore at the specified offset into the
 * destination buffer.
 *
 * Return:
 * EL2GO_AGENT_SUCCESS on success, error code otherwise
 */
el2go_agent_t el2go_agent_datastore_read(el2go_agent_datastore_t *datastore,
					 void *dest, size_t offset, size_t len);

/**
 * el2go_agent_datastore_write - Write data to the datastore
 * @datastore: Datastore
 * @src: Source buffer
 * @offset: Offset in the datastore to write to
 * @len: Number of bytes to write
 *
 * Writes len bytes from the source buffer to the datastore at the
 * specified offset.
 *
 * Return:
 * EL2GO_AGENT_SUCCESS on success, error code otherwise
 */
el2go_agent_t el2go_agent_datastore_write(el2go_agent_datastore_t *datastore,
					  const void *src, size_t offset,
					  size_t len);

/**
 * el2go_agent_datastore_commit - Commit a transaction to the datastore
 * @datastore: Datastore
 *
 * Commits pending changes to the datastore.
 *
 * Return:
 * EL2GO_AGENT_SUCCESS on success, error code otherwise
 */
el2go_agent_t el2go_agent_datastore_commit(el2go_agent_datastore_t *datastore);

/*
 * EdgeLock 2GO datastore configuration
 */
/* clang-format off */
typedef struct {
	const char *hostname;                    /* Server hostname */
	uint16_t port;                           /* Server port */
	const el2go_agent_buffer_t *certificate; /* Server certificate */
} el2go_agent_el2go_config_t;
/* clang-format on */

/**
 * el2go_agent_datastore_el2go - Configure EdgeLock 2GO datastore
 * @datastore: Datastore
 * @keystore_ctx: Keystore context for secure operations
 * @config: EdgeLock 2GO configuration
 *
 * Configures the EdgeLock 2GO datastore with connection parameters.
 * If certificate is NULL or certificate->data is NULL, compile-time defaults
 * will be used for the server certificate. Missing hostname or port will also
 * use defaults.
 *
 * Return:
 * EL2GO_AGENT_SUCCESS on success, error code otherwise
 */
el2go_agent_t
el2go_agent_datastore_el2go(el2go_agent_datastore_t *datastore,
			    el2go_agent_keystore_t *keystore_ctx,
			    const el2go_agent_el2go_config_t *config);

/**
 * el2go_agent_datastore_free - Free a datastore
 * @datastore: Pointer to datastore (will be set to NULL)
 *
 * This function frees all datastore resources.
 *
 * Return:
 * EL2GO_AGENT_SUCCESS on success, error code otherwise
 */
el2go_agent_t el2go_agent_datastore_free(el2go_agent_datastore_t *datastore);

#endif /* __EL2GO_AGENT_DATASTORE_H__ */