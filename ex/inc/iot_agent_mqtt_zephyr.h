/* 
 * Copyright 2024 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 * 
 */

#ifndef _IOT_AGENT_MQTT_ZEPHYR_H_
#define _IOT_AGENT_MQTT_ZEPHYR_H_

#include <nxp_iot_agent.h>
   
#ifdef __cplusplus
extern "C" {
#endif

iot_agent_status_t iot_agent_verify_mqtt_connection_cos_over_rtp(iot_agent_context_t* iot_agent_context, const nxp_iot_ServiceDescriptor* service_descriptor);

iot_agent_status_t iot_agent_cleanup_mqtt_config_files_cos_over_rtp(void);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // #ifndef _IOT_AGENT_MQTT_ZEPHYR_H_
