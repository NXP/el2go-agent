# Copyright 2026 NXP
# SPDX-License-Identifier: Apache-2.0

# Zephyr mbedTLS backend - overrides the weak el2go_mqtt_verify() default.
include(add_target_sources)
zephyr_library_sources_ifdef(CONFIG_EL2GO_RTP_MQTT_VERIFY el2go_mqtt_zephyr.c)

# Inject MQTT key/cert IDs into this library target. Kconfig only.
add_lib_config_hex(el2go_mqtt CONFIG_EL2GO_RTP_MQTT_AWS_KEY_ID    AWS_SERVICE_KEY_PAIR_ID    0x0)
add_lib_config_hex(el2go_mqtt CONFIG_EL2GO_RTP_MQTT_AWS_CERT_ID   AWS_SERVICE_DEVICE_CERT_ID 0x0)
add_lib_config_hex(el2go_mqtt CONFIG_EL2GO_RTP_MQTT_AZURE_KEY_ID  AZURE_SERVICE_KEY_PAIR_ID  0x0)
add_lib_config_hex(el2go_mqtt CONFIG_EL2GO_RTP_MQTT_AZURE_CERT_ID AZURE_SERVICE_DEVICE_CERT_ID 0x0)
