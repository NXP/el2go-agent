# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0

add_library(el2go_common OBJECT
    el2go_service.c
    el2go_server_certificates.c
    el2go_server_connection.c
)

target_include_directories(el2go_common
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
    PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/priv
)

target_link_libraries(el2go_common
    PRIVATE
        el2go_protobuf
        el2go_datastore
        el2go_keystore
        osal
	net_crypto
)