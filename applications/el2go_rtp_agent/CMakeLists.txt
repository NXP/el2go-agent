# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

cmake_minimum_required(VERSION ${CMAKE_MINIMUM_REQUIRED_VERSION})
project(el2go_rtp_agent VERSION ${CMAKE_PROJECT_VERSION} LANGUAGES C)

include(sources.cmake)

# EL2GO RTP Agent demo
add_executable(${PROJECT_NAME} ${EL2GO_RTP_AGENT_SOURCES})

target_include_directories(${PROJECT_NAME} PRIVATE
    ${PROJECT_ROOT}/libs/osal/include
    ${PROJECT_ROOT}/applications/common/network
    ${PROJECT_ROOT}/applications/common/mqtt
)

target_link_libraries(${PROJECT_NAME} PRIVATE el2go_rtp el2go_mqtt el2go_app_net)

# Installation rules
install(TARGETS ${PROJECT_NAME}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
