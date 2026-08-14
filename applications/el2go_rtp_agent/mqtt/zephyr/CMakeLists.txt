# Copyright 2026 NXP
# SPDX-License-Identifier: Apache-2.0

# Zephyr mbedTLS backend - overrides the weak el2go_mqtt_verify() default.
include(add_target_sources)
add_private_sources(el2go_mqtt el2go_mqtt_zephyr.c)
