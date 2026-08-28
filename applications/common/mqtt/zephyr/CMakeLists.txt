# Copyright 2026 NXP
# SPDX-License-Identifier: Apache-2.0

# Zephyr mbedTLS backend - overrides the weak el2go_mqtt_verify() default.
include(add_target_sources)
zephyr_library_sources_ifdef(CONFIG_EL2GO_RTP_MQTT_VERIFY el2go_mqtt_zephyr.c)
