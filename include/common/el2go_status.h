/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright 2018-2026 NXP
 */

#ifndef __EL2GO_STATUS_H__
#define __EL2GO_STATUS_H__

/**
 * el2go_agent_status.h - Status and return types for RTP Agent
 */

/**
 * enum el2go_status_t - RTP Agent return type
 * @EL2GO_STATUS_SUCCESS: Operation successful
 * @EL2GO_STATUS_FAILURE: Operation failed
 *
 * @EL2GO_STATUS_FILE_OPEN_ERROR: File open operation error
 * @EL2GO_STATUS_FILE_CLOSE_ERROR: File close operation error
 * @EL2GO_STATUS_FILE_READ_ERROR: File read operation error
 * @EL2GO_STATUS_FILE_WRITE_ERROR: File write/flush operation error
 * @EL2GO_STATUS_FILE_SEEK_ERROR: File seek operation error
 *
 * @EL2GO_STATUS_INVALID_POINTER: A pointer is invalid
 * @EL2GO_STATUS_ALLOCATION_ERROR: Memory allocation failed
 * @EL2GO_STATUS_BUFFER_TOO_SMALL: Buffer size is too small
 * @EL2GO_STATUS_INVALID_PARAMETER: Invalid parameter provided
 * @EL2GO_STATUS_INVALID_STATE: Invalid state for operation
 * @EL2GO_STATUS_ARITHMETIC_OVERFLOW: Arithmetic overflow detected
 * @EL2GO_STATUS_RESOURCE_LIMIT: Resource limit reached
 * @EL2GO_STATUS_ALREADY_EXISTS: Resource already exists
 * @EL2GO_STATUS_NOT_FOUND: Resource not found
 */
typedef enum el2go_status_t {
	EL2GO_STATUS_SUCCESS = 0,
	EL2GO_STATUS_FAILURE,
	EL2GO_STATUS_FILE_OPEN_ERROR,
	EL2GO_STATUS_FILE_CLOSE_ERROR,
	EL2GO_STATUS_FILE_READ_ERROR,
	EL2GO_STATUS_FILE_WRITE_ERROR,
	EL2GO_STATUS_FILE_SEEK_ERROR,
	EL2GO_STATUS_INVALID_POINTER,
	EL2GO_STATUS_ALLOCATION_ERROR,
	EL2GO_STATUS_BUFFER_TOO_SMALL,
	EL2GO_STATUS_INVALID_PARAMETER,
	EL2GO_STATUS_INVALID_STATE,
	EL2GO_STATUS_ARITHMETIC_OVERFLOW,
	EL2GO_STATUS_RESOURCE_LIMIT,
	EL2GO_STATUS_ALREADY_EXISTS,
	EL2GO_STATUS_NOT_FOUND
} el2go_status_t;

/**
 * enum el2go_verbosity_t - Status report verbosity levels
 * @EL2GO_STATUS_SILENT: Do not print status report
 * @EL2GO_STATUS_ON_ERROR: Print status report only on error
 * @EL2GO_STATUS_ALWAYS: Always print status report
 */
typedef enum {
	EL2GO_STATUS_SILENT,
	EL2GO_STATUS_ON_ERROR,
	EL2GO_STATUS_ALWAYS
} el2go_verbosity_t;

#endif /* __EL2GO_STATUS_H__ */
