# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

add_subdirectory(fs)
add_subdirectory(plain)

# Main datastore object library with common interface
add_library(el2go_datastore OBJECT
    el2go_datastore.c
    ${DATASTORE_FS_SOURCES}
    ${DATASTORE_PLAIN_SOURCES}
)

target_include_directories(el2go_datastore
    PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/fs
        ${CMAKE_CURRENT_SOURCE_DIR}/plain
        ${CMAKE_SOURCE_DIR}/priv
        ${CMAKE_SOURCE_DIR}/libs/osal/include
)
