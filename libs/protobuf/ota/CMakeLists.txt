# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

include(add_target_sources)

declare_library(ota_protobuf)

add_private_sources(ota_protobuf
    types/available_updates_request.pb.c
    types/available_updates_response.pb.c
    types/download_status.pb.c
    types/download_status_notification.pb.c
    types/file_metadata.pb.c
    types/file_request.pb.c
    types/file_response.pb.c
    types/package.pb.c
    types/range.pb.c
    types/update.pb.c
    types/update_status.pb.c
    types/update_status_notification.pb.c
)

add_public_directories(ota_protobuf
    ${CMAKE_CURRENT_SOURCE_DIR}
)

add_link_libraries(ota_protobuf
    PUBLIC
        nanopb
)