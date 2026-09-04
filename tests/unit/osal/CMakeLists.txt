# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0

add_library(test_osal EXCLUDE_FROM_ALL OBJECT
    test_env.c
)

target_include_directories(test_osal
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
    PRIVATE
        ${CMAKE_SOURCE_DIR}/priv
)

add_subdirectory(${OS})
