# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

include(add_target_sources)

set(OSAL_SOURCES
    alloc.c
    osal.c
    print.c
    file.c
    uuid.c
)

declare_library(osal)

add_private_sources(osal ${OSAL_SOURCES})

add_public_directories(osal
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
)

add_private_directories(osal
    ${CMAKE_CURRENT_SOURCE_DIR}
)
