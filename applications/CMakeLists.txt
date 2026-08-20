# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

if(NOT DEFINED PROJECT_ROOT)
    set(PROJECT_ROOT ${CMAKE_SOURCE_DIR})
endif()

add_subdirectory(common)
add_subdirectory(el2go_rtp_agent)
add_subdirectory(ota_agents)
