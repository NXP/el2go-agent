# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(el2go_ota_tests)

target_sources(app PRIVATE
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/tests/unit/framework/test_framework.c
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/tests/unit/framework/test_utils.c
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/tests/unit/public_fwual/test_fwual_public.c
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/tests/unit/public_ota_lib/test_el2go_ota_lib_public.c
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/tests/unit/public_ota_agent_core/test_el2go_ota_agent_core_public.c
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/tests/unit/public_ota_agent_advanced/test_el2go_ota_agent_advanced_public.c
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/tests/unit/osal/zephyr/zephyr_main.c
)

zephyr_include_directories(
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/tests/unit/framework
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/tests/unit
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/include
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/priv
)
