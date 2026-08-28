# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

set(EL2GO_RTP_AGENT_SOURCES
    ${CMAKE_CURRENT_LIST_DIR}/src/el2go_rtp_agent_demo.c
)

set(EL2GO_RTP_AGENT_INCLUDE_DIRS
    ${CMAKE_CURRENT_LIST_DIR}/inc
)

# OS-specific osal_types dispatch
list(APPEND EL2GO_RTP_AGENT_INCLUDE_DIRS
    ${CMAKE_CURRENT_LIST_DIR}/osal/${OS}/inc
)
