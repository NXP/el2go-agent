# Copyright 2026 NXP
# SPDX-License-Identifier: Apache-2.0

include(add_target_sources)

declare_library(el2go_ota_download)

add_private_sources(el2go_ota_download
    ${CMAKE_CURRENT_SOURCE_DIR}/el2go_ota_download_engine.c
)

add_public_directories(el2go_ota_download
    ${CMAKE_CURRENT_SOURCE_DIR}
)

add_private_directories(el2go_ota_download
    ${PROJECT_ROOT}/priv
    ${PROJECT_ROOT}/include
    ${PROJECT_ROOT}/libs/osal/include
    ${PROJECT_ROOT}/libs/el2go_ota_lib/src
)

add_link_libraries(el2go_ota_download
    PRIVATE
        el2go_ota_transport
        el2go_ota_osal
)
