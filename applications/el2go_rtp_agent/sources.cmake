# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

# Sources shared between the bare-metal and Zephyr builds.
# Zephyr-only files (e.g. mqtt/) are added directly in
# zephyr/samples/el2go_rtp_agent/CMakeLists.txt.
set(EL2GO_RTP_AGENT_SOURCES
    ${CMAKE_CURRENT_LIST_DIR}/src/el2go_rtp_agent_demo.c
)
