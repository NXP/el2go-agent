# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0

include(add_target_sources)

add_subdirectory(fs)
add_subdirectory(plain)

declare_library(el2go_datastore)

add_private_sources(el2go_datastore
    el2go_datastore.c
    ${DATASTORE_FS_SOURCES}
    ${DATASTORE_PLAIN_SOURCES}
)

add_public_directories(el2go_datastore
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/fs
    ${CMAKE_CURRENT_SOURCE_DIR}/plain
)

add_private_directories(el2go_datastore
    ${PROJECT_ROOT}/include
    ${PROJECT_ROOT}/priv
    ${PROJECT_ROOT}/libs/osal/include
)

add_link_libraries(el2go_datastore
    PRIVATE
        el2go_protobuf
        pb_utils
)
