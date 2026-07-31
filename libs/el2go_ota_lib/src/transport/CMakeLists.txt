# Copyright 2026 NXP
# SPDX-License-Identifier: Apache-2.0

include(add_target_sources)

declare_library(el2go_ota_transport)

add_private_sources(el2go_ota_transport
    ${CMAKE_CURRENT_SOURCE_DIR}/el2go_ota_transport_init.c
)

add_public_directories(el2go_ota_transport
    ${CMAKE_CURRENT_SOURCE_DIR}
)

add_private_directories(el2go_ota_transport
    ${PROJECT_ROOT}/priv
    ${PROJECT_ROOT}/include
    ${PROJECT_ROOT}/libs/osal/include
)

if(NOT IS_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/${EL2GO_OTA_TRANSPORT})
    message(FATAL_ERROR
        "Unknown transport backend '${EL2GO_OTA_TRANSPORT}'. ")
endif()

add_subdirectory(${EL2GO_OTA_TRANSPORT})
