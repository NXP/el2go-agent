# Copyright 2026 NXP
# SPDX-License-Identifier: Apache-2.0

include(add_target_sources)

declare_library(el2go_mqtt)

add_private_sources(el2go_mqtt
    el2go_mqtt.c
)

add_public_directories(el2go_mqtt
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${PROJECT_ROOT}/include
)

if(CONFIG_EL2GO_RTP_MQTT_VERIFY)
    add_subdirectory(zephyr)
endif()
