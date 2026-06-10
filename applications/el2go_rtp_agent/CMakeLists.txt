# Copyright 2026 NXP
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION ${CMAKE_MINIMUM_REQUIRED_VERSION})
project(el2go_rtp_agent VERSION ${CMAKE_PROJECT_VERSION} LANGUAGES C)

# EL2GO RTP Agent demo
add_executable(${PROJECT_NAME} src/el2go_rtp_agent_demo.c)
target_link_libraries(${PROJECT_NAME} PRIVATE el2go_rtp)

# Installation rules
install(TARGETS ${PROJECT_NAME}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
