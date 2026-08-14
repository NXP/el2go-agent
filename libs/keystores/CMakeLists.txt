# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

include(add_target_sources)

declare_library(el2go_keystore)

add_private_sources(el2go_keystore
    el2go_keystore.c
)

add_public_directories(el2go_keystore
    ${CMAKE_CURRENT_SOURCE_DIR}
)

add_private_directories(el2go_keystore
    ${PROJECT_ROOT}/include
    ${PROJECT_ROOT}/priv
    ${PROJECT_ROOT}/libs/osal/include
    ${PROJECT_ROOT}/libs/platforms
)

if(NOT DEFINED KEYSTORE)
    set(KEYSTORE psa)
endif()

message(STATUS "EdgeLock 2GO Keystore: ${KEYSTORE}")
add_subdirectory(${KEYSTORE})
