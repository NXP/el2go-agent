# Copyright 2024 NXP
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})

project(el2go_agent)

target_sources(app PRIVATE
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/ex/src/iot_agent_demo.c
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/ex/src/network/iot_agent_network_zephyr_wifi.c
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/ex/src/utils/iot_agent_claimcode_import.c
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/ex/src/utils/iot_agent_mqtt_zephyr.c
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/ex/src/utils/mbedtls_psa/iot_agent_psa_sign_test.c
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/ex/src/osal/iot_agent_osal_zephyr.c
)

zephyr_include_directories(
    $<TARGET_PROPERTY:tfm,TFM_BINARY_DIR>/api_ns/interface/include
    ${APPLICATION_SOURCE_DIR}/inc
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/ex/inc
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/ex/inc/mbedtls_psa
)
