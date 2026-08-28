# Copyright 2026 NXP
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})

project(el2go_rtp_agent)

zephyr_include_directories(
    ${APPLICATION_SOURCE_DIR}/inc
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/applications/el2go_rtp_agent/inc
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/applications/el2go_rtp_agent/osal/zephyr/inc
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/applications/common/time
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/applications/common/system
)

include(${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/applications/el2go_rtp_agent/sources.cmake)
target_sources(app PRIVATE ${EL2GO_RTP_AGENT_SOURCES})
