# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

cmake_minimum_required(VERSION ${CMAKE_MINIMUM_REQUIRED_VERSION})
project(el2go_ota_agent_advanced VERSION ${CMAKE_PROJECT_VERSION} LANGUAGES C)

include(sources.cmake)
# EL2GO OTA Agent Advanced application
add_executable(${PROJECT_NAME} ${EL2GO_OTA_AGENT_ADVANCED_SOURCES})

target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(${PROJECT_NAME} PRIVATE fwual el2go_ota_lib)

# Installation rules
install(TARGETS ${PROJECT_NAME}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
