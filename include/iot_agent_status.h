/*
 * Copyright 2018-2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __IOT_AGENT_STATUS_H__
#define __IOT_AGENT_STATUS_H__

/**
 * iot_agent_status.h - Status and return types for IoT Agent
 */

/**
 * enum iot_agent_t - IoT Agent return type
 * @IOT_AGENT_SUCCESS: Operation successful
 * @IOT_AGENT_FAILURE: Operation failed
 */
typedef enum iot_agent_t {
    IOT_AGENT_SUCCESS = 0,
    IOT_AGENT_FAILURE
} iot_agent_t;

#endif /* __IOT_AGENT_STATUS_H__ */