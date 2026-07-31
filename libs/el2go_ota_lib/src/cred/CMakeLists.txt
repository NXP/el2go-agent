# Copyright 2026 NXP
# SPDX-License-Identifier: Apache-2.0

include(add_target_sources)

declare_library(el2go_ota_cred)

if(NOT IS_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/${EL2GO_OTA_CRED})
    message(FATAL_ERROR
        "Unknown credential provider '${EL2GO_OTA_CRED}'. ")
endif()

add_subdirectory(${EL2GO_OTA_CRED})

add_public_directories(el2go_ota_cred
    ${CMAKE_CURRENT_SOURCE_DIR}
)
