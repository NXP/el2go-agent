# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

# Add PSA-specific keystore sources directly to parent target
target_sources(el2go_keystore PRIVATE
    el2go_keystore_psa.c
)

# Add PSA headers include directories
target_link_libraries(el2go_keystore PRIVATE
    el2go_protobuf
    el2go_platform
)
