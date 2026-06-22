# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

# OSAL Linux implementation object library
add_library(osal OBJECT
        alloc.c
        osal.c
        print.c
        file.c
        uuid.c
)

target_include_directories(osal
        PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/../include
        PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/priv
        ${CMAKE_CURRENT_SOURCE_DIR}
)
