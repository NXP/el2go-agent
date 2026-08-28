# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

include(add_target_sources)

declare_library(el2go_platform)

add_private_sources(el2go_platform
    el2go_platform.c
    plat_crypto_params.c
)

add_public_directories(el2go_platform
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/${PLATFORM}
)

add_private_directories(el2go_platform
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/priv
    ${CMAKE_SOURCE_DIR}/libs/osal/include
)

message(STATUS "EdgeLock 2GO Platform: ${PLATFORM}")
add_subdirectory(${PLATFORM})