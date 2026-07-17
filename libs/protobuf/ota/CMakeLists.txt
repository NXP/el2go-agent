# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

include(add_target_sources)

# OTA delivery protobuf definitions.
# declare_library creates an OBJECT library in non-Zephyr builds; in Zephyr
# builds it is a no-op because sources are contributed to the Zephyr library
# directly via the add_private_sources / add_public_directories macros below.

declare_library(ota_protobuf)

add_private_sources(ota_protobuf
    ota_delivery.pb.c
)

add_public_directories(ota_protobuf
    ${CMAKE_CURRENT_SOURCE_DIR}
)

add_link_libraries(ota_protobuf
    PUBLIC
        nanopb
)
