# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

add_subdirectory(common)
add_subdirectory(el2go_rtp_agent)

if(BUILD_OTA)
    add_subdirectory(ota_agents)
endif()

if(NOT OS STREQUAL "linux")
    add_subdirectory(el2go_csr)
    add_subdirectory(el2go_import_blob)
    add_subdirectory(el2go_claimcode_encryption)
endif()