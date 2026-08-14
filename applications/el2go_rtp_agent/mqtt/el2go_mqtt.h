/*
 * Copyright 2026 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef APPLICATIONS_EL2GO_RTP_AGENT_MQTT_EL2GO_MQTT_H_
#define APPLICATIONS_EL2GO_RTP_AGENT_MQTT_EL2GO_MQTT_H_

#include "common/el2go_keystore.h"

/**
 * @brief Verify MQTT credentials provisioned by the EL2GO RTP agent.
 *
 * Attempts a TLS connection to the configured MQTT broker using the
 * device key and certificate stored in the PSA keystore.  Supported
 * backends are selected at build time via Kconfig:
 *   CONFIG_EL2GO_RTP_MQTT_AWS   - AWS IoT Core
 *                                 key  PSA ID CONFIG_EL2GO_RTP_MQTT_AWS_KEY_ID  (default 0x83000101)
 *                                 cert PSA UID CONFIG_EL2GO_RTP_MQTT_AWS_CERT_ID (default 0x83000102)
 *   CONFIG_EL2GO_RTP_MQTT_AZURE - Azure IoT Hub via DPS
 *                                 key  PSA ID CONFIG_EL2GO_RTP_MQTT_AZURE_KEY_ID  (default 0x83000211)
 *                                 cert PSA UID CONFIG_EL2GO_RTP_MQTT_AZURE_CERT_ID (default 0x83000212)
 *
 * Root CA blobs and service-specific configuration (ID scope, hostname, etc.)
 * are centralised in el2go_mqtt_config.h (generated from Kconfig symbols).
 *
 * A weak default implementation (no-op) is provided in el2go_mqtt.c.
 * OS-specific backends (e.g. zephyr/el2go_mqtt_zephyr.c) override it.
 *
 * @param keystore  Pointer to the initialised keystore context.
 * @return 0 on success, negative errno on failure.
 */
int el2go_mqtt_verify(el2go_keystore_t *keystore);

#endif /* APPLICATIONS_EL2GO_RTP_AGENT_MQTT_EL2GO_MQTT_H_ */
