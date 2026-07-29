# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

include(add_target_sources)

declare_static_library(nanopb)

add_private_sources(nanopb
    pb_common.c
    pb_decode.c
    pb_encode.c
)

add_public_directories(nanopb
    ${CMAKE_CURRENT_SOURCE_DIR}
)

add_public_definitions(nanopb
    PB_FIELD_32BIT=1
    PB_ENABLE_MALLOC=1
)