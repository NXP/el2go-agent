# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

# Nanopb runtime library
add_library(nanopb STATIC
    pb_common.c
    pb_decode.c
    pb_encode.c
)

target_include_directories(nanopb PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Define PB_FIELD_32BIT for nanopb to support very large messages
target_compile_definitions(nanopb PUBLIC
    PB_FIELD_32BIT=1
)
