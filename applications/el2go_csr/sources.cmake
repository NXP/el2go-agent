# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#
# Common (platform-agnostic) sources and include directories for the
# el2go_csr application.
#
# OS- and board-specific files are NOT listed here. They are added by
# each build entry point (Zephyr sample, standalone CMakeLists.txt, etc.)
# using the appropriate platform selection mechanism.

set(EL2GO_CSR_SOURCES_DIR ${CMAKE_CURRENT_LIST_DIR})

# --- Common sources (always compiled, any OS/board) ---
set(EL2GO_CSR_APP_SOURCES
    # Application logic
    ${EL2GO_CSR_SOURCES_DIR}/app/src/el2go_csr.c
    ${EL2GO_CSR_SOURCES_DIR}/app/src/el2go_csr_tlv_parser.c
    # Common utilities
    ${EL2GO_CSR_SOURCES_DIR}/common/src/csr_util.c
)

# --- Common include directories (shared base, any OS/board) ---
# OS-specific and board-specific subdirs are appended by the caller.
set(EL2GO_CSR_INCLUDE_DIRS
    ${EL2GO_CSR_SOURCES_DIR}/app/inc
    ${EL2GO_CSR_SOURCES_DIR}/common/inc
    ${EL2GO_CSR_SOURCES_DIR}/../common/utils
    ${EL2GO_CSR_SOURCES_DIR}/osal/inc
    ${EL2GO_CSR_SOURCES_DIR}/pal/inc
    ${EL2GO_CSR_SOURCES_DIR}/port
)
