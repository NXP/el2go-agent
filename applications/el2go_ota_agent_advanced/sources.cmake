# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

# Sources shared between the bare-metal and Zephyr builds.
# Zephyr-only or bare-metal-only files are added directly in their
# respective CMakeLists.txt, not here.
set(EL2GO_OTA_AGENT_ADVANCED_SOURCES
    ${CMAKE_CURRENT_LIST_DIR}/src/main.c
)
