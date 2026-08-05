# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

include(add_target_sources)

# Handwritten protobuf utility helpers (not generated)
declare_library(pb_utils)

add_private_sources(pb_utils
    pb_utils.c
)

add_public_directories(pb_utils
    ${CMAKE_CURRENT_SOURCE_DIR}
)

add_link_libraries(pb_utils
    PUBLIC
        el2go_protobuf
)
