# Copyright 2026 NXP
# SPDX-License-Identifier: Apache-2.0

include(add_target_sources)

add_private_sources(el2go_ota_transport
    ${CMAKE_CURRENT_SOURCE_DIR}/el2go_ota_grpc.c
)

add_private_directories(el2go_ota_transport
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${PROJECT_ROOT}/libs/el2go_ota_lib/src
)
