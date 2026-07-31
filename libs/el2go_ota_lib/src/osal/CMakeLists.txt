# Copyright 2026 NXP
# SPDX-License-Identifier: Apache-2.0

include(add_target_sources)

declare_library(el2go_ota_osal)

add_private_sources(el2go_ota_osal
    ${CMAKE_CURRENT_SOURCE_DIR}/el2go_ota_kvs.c
)

add_public_directories(el2go_ota_osal
    ${CMAKE_CURRENT_SOURCE_DIR}
)

add_private_directories(el2go_ota_osal
    ${PROJECT_ROOT}/priv
    ${PROJECT_ROOT}/include
)

if(NOT IS_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/${OS})
    message(FATAL_ERROR
        "Unknown OS '${OS}'. ")
endif()

add_subdirectory(${OS})
