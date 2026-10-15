# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

cmake_minimum_required(VERSION ${CMAKE_MINIMUM_REQUIRED_VERSION})
project(el2go_rtp_agent VERSION ${CMAKE_PROJECT_VERSION} LANGUAGES C)

include(add_target_sources)
include(sources.cmake)

# EL2GO RTP Agent demo
add_executable(${PROJECT_NAME} ${EL2GO_RTP_AGENT_SOURCES})

target_include_directories(${PROJECT_NAME} PRIVATE
    ${EL2GO_RTP_AGENT_INCLUDE_DIRS}
    ${PROJECT_ROOT}/applications/common/time
    ${PROJECT_ROOT}/applications/common/system
    ${PROJECT_ROOT}/applications/common/network
    ${PROJECT_ROOT}/applications/common/mqtt
    ${PROJECT_ROOT}/applications/common/osal
    ${PROJECT_ROOT}/libs/osal/include
)

# Enable INFO, WARN, and ERROR log levels by default for Linux builds
target_compile_definitions(${PROJECT_NAME} PRIVATE
    ENABLE_EL2GO_RTP_INFO=1
    ENABLE_EL2GO_RTP_WARN=1
    ENABLE_EL2GO_RTP_ERROR=1
)

target_link_libraries(${PROJECT_NAME} PRIVATE el2go_rtp el2go_mqtt el2go_app_net)

# Installation rules
install(TARGETS ${PROJECT_NAME}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# Credentials: CMake -D value takes priority; fall back to OS env var.
add_config_string(${PROJECT_NAME} EL2GO_RTP_EDGELOCK2GO_HOSTNAME EL2GO_RTP_EDGELOCK2GO_HOSTNAME)
add_config_hex(${PROJECT_NAME} AWS_SERVICE_KEY_PAIR_ID    AWS_SERVICE_KEY_PAIR_ID    0x0)
add_config_hex(${PROJECT_NAME} AWS_SERVICE_DEVICE_CERT_ID AWS_SERVICE_DEVICE_CERT_ID 0x0)
add_config_hex(${PROJECT_NAME} AZURE_SERVICE_KEY_PAIR_ID  AZURE_SERVICE_KEY_PAIR_ID  0x0)
add_config_hex(${PROJECT_NAME} AZURE_SERVICE_DEVICE_CERT_ID AZURE_SERVICE_DEVICE_CERT_ID 0x0)
add_config_hex(${PROJECT_NAME} EL2GO_RTP_CLAIMCODE_FLASH_ADDRESS EL2GO_RTP_CLAIMCODE_FLASH_ADDRESS 0x0)
