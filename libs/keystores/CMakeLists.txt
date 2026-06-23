# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

set(KEYSTORE_SOURCES
    el2go_keystore.c
)

# Create keystore library
add_library(el2go_keystore OBJECT)

# Set keystore-specific include directory
target_include_directories(el2go_keystore
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
    PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/priv
        ${CMAKE_SOURCE_DIR}/libs/osal/include
        ${CMAKE_SOURCE_DIR}/libs/platforms
)

message(STATUS "EdgeLock 2GO Keystore: ${KEYSTORE}")
add_subdirectory(${KEYSTORE})

target_sources(el2go_keystore PRIVATE ${KEYSTORE_SOURCES})
