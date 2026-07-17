# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

include(add_target_sources)

# Nanopb runtime library.
# declare_library creates an OBJECT library in non-Zephyr builds; in Zephyr
# builds it is a no-op because sources are contributed to the Zephyr library
# directly via the macros below.

declare_library(nanopb)

add_private_sources(nanopb
    pb_common.c
    pb_decode.c
    pb_encode.c
)

add_public_directories(nanopb
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# PB_FIELD_32BIT and PB_ENABLE_MALLOC must be PUBLIC so that all consumers
# of the nanopb headers receive the same definitions.
add_public_definitions(nanopb
    PB_FIELD_32BIT=1
    PB_ENABLE_MALLOC=1
)
