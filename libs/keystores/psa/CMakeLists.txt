# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

# Add PSA-specific keystore sources directly to parent target
target_sources(el2go_keystore PRIVATE
    el2go_keystore_psa.c
)

# Add protobuf include directory
target_include_directories(el2go_keystore PRIVATE
    ${CMAKE_SOURCE_DIR}/libs/protobuf
)

# Add PSA headers include directories
target_link_libraries(el2go_keystore PRIVATE
    psa_headers
    el2go_protobuf
)
