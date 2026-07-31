# Copyright 2026 NXP
# SPDX-License-Identifier: Apache-2.0

include(add_target_sources)

add_private_sources(el2go_ota_cred
    ${CMAKE_CURRENT_SOURCE_DIR}/el2go_ota_cred_psa.c
)

add_private_directories(el2go_ota_cred
    ${PROJECT_ROOT}/priv
    ${PROJECT_ROOT}/include
    ${PROJECT_ROOT}/libs/osal/include
)

add_link_libraries(el2go_ota_cred
    PRIVATE
        el2go_platform
)
