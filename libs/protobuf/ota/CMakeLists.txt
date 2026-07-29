# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

include(add_target_sources)

declare_static_library(ota_protobuf)

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