# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0

include(add_target_sources)

declare_library(el2go_common)

add_private_sources(el2go_common
    el2go_service.c
    el2go_server_certificates.c
    el2go_server_connection.c
)

add_public_directories(el2go_common
    ${CMAKE_CURRENT_SOURCE_DIR}
)

add_private_directories(el2go_common
    ${PROJECT_ROOT}/include
    ${PROJECT_ROOT}/priv
    ${PROJECT_ROOT}/libs/osal/include
)

add_link_libraries(el2go_common
    PRIVATE
        el2go_protobuf
        el2go_datastore
        el2go_keystore
        osal
        net_crypto
)
