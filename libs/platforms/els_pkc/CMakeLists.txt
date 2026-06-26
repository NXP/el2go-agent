# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

target_sources(el2go_platform PRIVATE
    els_pkc_platform.c
)

target_include_directories(el2go_platform PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)
