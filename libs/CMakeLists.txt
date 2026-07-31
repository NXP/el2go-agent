# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

if(NOT DEFINED PROJECT_ROOT)
    set(PROJECT_ROOT ${CMAKE_SOURCE_DIR})
endif()

# Add common component subdirectories (shared between main libraries)
add_subdirectory(protobuf)
add_subdirectory(platforms)
add_subdirectory(keystores)
add_subdirectory(datastores)
add_subdirectory(osal/${OS})
add_subdirectory(net_crypto)
add_subdirectory(common)


# Add EL2GO RTP library subdirectories
add_subdirectory(el2go_rtp_lib)

# Add OTA library subdirectories
add_subdirectory(fwual)
add_subdirectory(el2go_ota_lib)
