# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

cmake_minimum_required(VERSION ${CMAKE_MINIMUM_REQUIRED_VERSION})
project(el2go_blob_test VERSION ${CMAKE_PROJECT_VERSION} LANGUAGES C)

include(sources.cmake)

add_executable(${PROJECT_NAME} ${EL2GO_BLOB_TEST_SOURCES})

target_include_directories(${PROJECT_NAME} PRIVATE
    ${EL2GO_BLOB_TEST_INCLUDE_DIRS}
)
