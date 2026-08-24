# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

cmake_minimum_required(VERSION ${CMAKE_MINIMUM_REQUIRED_VERSION})
project(el2go_claimcode_encryption VERSION ${CMAKE_PROJECT_VERSION} LANGUAGES C)

include(sources.cmake)

add_executable(${PROJECT_NAME} ${EL2GO_CLAIMCODE_ENCRYPTION_SOURCES})

target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/include/rtp
    ${CMAKE_CURRENT_SOURCE_DIR}/inc
    ${CMAKE_CURRENT_SOURCE_DIR}/flash_config
    ${CMAKE_SOURCE_DIR}/applications/common/config
)

target_link_libraries(${PROJECT_NAME} PRIVATE el2go_platform)

install(TARGETS ${PROJECT_NAME}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
