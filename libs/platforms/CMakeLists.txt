# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

set(PLATFORM_SOURCES
    el2go_platform.c
    plat_crypto_params.c
)

# Create platform library
add_library(el2go_platform OBJECT ${PLATFORM_SOURCES})

# Set platform-specific include directory
target_include_directories(el2go_platform
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/${PLATFORM}
    PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/priv
        ${CMAKE_SOURCE_DIR}/libs/osal/include
)

message(STATUS "EdgeLock 2GO Platform: ${PLATFORM}")
add_subdirectory(${PLATFORM})
