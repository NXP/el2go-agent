# Copyright 2024-2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

cmake_minimum_required(VERSION ${CMAKE_MINIMUM_REQUIRED_VERSION})
project(el2go_import_blob VERSION ${CMAKE_PROJECT_VERSION} LANGUAGES C)

include(sources.cmake)

add_executable(${PROJECT_NAME} ${EL2GO_IMPORT_BLOB_SOURCES})

target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../common/utils
)

target_link_libraries(${PROJECT_NAME} PRIVATE net_crypto el2go_platform)

install(TARGETS ${PROJECT_NAME}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
