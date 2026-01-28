/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright 2018-2026 NXP
 */

#ifndef __EL2GO_AGENT_STATUS_H__
#define __EL2GO_AGENT_STATUS_H__

/**
 * el2go_agent_status.h - Status and return types for IoT Agent
 */

/**
 * enum el2go_agent_t - IoT Agent return type
 * @EL2GO_AGENT_SUCCESS: Operation successful
 * @EL2GO_AGENT_FAILURE: Operation failed
 */
typedef enum el2go_agent_t {
	EL2GO_AGENT_SUCCESS = 0,
	EL2GO_AGENT_FAILURE
} el2go_agent_t;

/**
 * enum el2go_agent_verbosity_t - Status report verbosity levels
 * @EL2GO_AGENT_STATUS_SILENT: Do not print status report
 * @EL2GO_AGENT_STATUS_ON_ERROR: Print status report only on error
 * @EL2GO_AGENT_STATUS_ALWAYS: Always print status report
 */
typedef enum {
	EL2GO_AGENT_STATUS_SILENT,
	EL2GO_AGENT_STATUS_ON_ERROR,
	EL2GO_AGENT_STATUS_ALWAYS
} el2go_agent_verbosity_t;

#endif /* __EL2GO_AGENT_STATUS_H__ */