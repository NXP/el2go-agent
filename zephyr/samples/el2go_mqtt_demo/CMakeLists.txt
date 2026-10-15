# Copyright 2024-2026 NXP
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})

project(el2go_mqtt_demo)

if(CONFIG_BUILD_WITH_TFM)
    zephyr_include_directories(
        $<TARGET_PROPERTY:tfm,TFM_BINARY_DIR>/api_ns/interface/include
    )
endif()

target_sources(app PRIVATE
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/applications/el2go_mqtt_demo/src/el2go_mqtt_client.c
)

zephyr_include_directories(${APPLICATION_SOURCE_DIR}/inc)

target_include_directories(app PRIVATE
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/applications/common/mqtt
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/applications/common/network
)

include(${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/cmake/add_target_sources.cmake)

# EL2GO hostname injection for el2go_mqtt_demo.
add_config_string(app CONFIG_EL2GO_RTP_EDGELOCK2GO_HOSTNAME EL2GO_RTP_EDGELOCK2GO_HOSTNAME)
