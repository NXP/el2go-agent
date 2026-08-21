# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#
# ==============================================================================
#  Board Template — EL2GO CSR Application
# ==============================================================================
#
#  This file serves as a starting point for integrating a new board into the
#  EL2GO CSR build system. Copy this directory, rename it to match your board
#  (e.g. "my_board"), and adapt the sections below.
#
#  The parent CMakeLists.txt includes this file via:
#      add_subdirectory(pal/boards/<EL2GO_CSR_BOARD>)
#
#  Your CMakeLists.txt MUST provide the following:
#
#   1. EL2GO_CSR_BOARD_SOURCES   (variable, PARENT_SCOPE)
#      List of board-specific .c source files (e.g. BSP glue code).
#
#   2. EL2GO_CSR_BOARD_INCLUDE_DIRS   (variable, PARENT_SCOPE)
#      List of board-specific include directories.
#
#   3. el2go_csr_board_sdk   (CMake target, STATIC or INTERFACE)
#      A library target that encapsulates all vendor SDK sources, include
#      paths, compile definitions, and linker settings your board requires.
#
# ==============================================================================

cmake_minimum_required(VERSION 3.15)

# ==============================================================================
#  Step 1 — Point to your vendor SDK or BSP/CMSIS location
# ==============================================================================
# Set the root path of your board/vendor SDK. You can either hard-code it here
# or pass it as a cache variable from the command line:
#     cmake -DMY_BOARD_SDK_PATH=/path/to/sdk ...
#

set(BOARD_SDK_PATH "" CACHE PATH "Path to the board/vendor SDK")

if(NOT EXISTS "${BOARD_SDK_PATH}")
    message(FATAL_ERROR
        "BOARD_SDK_PATH not found: '${BOARD_SDK_PATH}'\n"
        "Set it via: cmake -DBOARD_SDK_PATH=/path/to/your/sdk ..."
    )
endif()

# ==============================================================================
#  Step 2 — Export board sources and include directories
# ==============================================================================
# Collect the .c files in this board directory (BSP glue, UART init, etc.)
# and expose them to the parent CMakeLists.txt.

file(GLOB _board_sources CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/*.c")

set(EL2GO_CSR_BOARD_SOURCES 
    ${_board_sources} 
    PARENT_SCOPE
)

set(EL2GO_CSR_BOARD_INCLUDE_DIRS
    ${CMAKE_CURRENT_SOURCE_DIR}/inc
    PARENT_SCOPE
)

# ==============================================================================
#  Step 3 — Create the el2go_csr_board_sdk target
# ==============================================================================
# This target wraps your vendor SDK. Add all SDK sources, include paths,
# compile definitions, startup files, and linker scripts here.

add_library(el2go_csr_board_sdk STATIC)

# --- 3a. Gather SDK sources (startup, HAL drivers, system files) ---

target_sources(el2go_csr_board_sdk PRIVATE
    # Add your SDK source paths here
)

# --- 3b. SDK include directories ---

target_include_directories(el2go_csr_board_sdk PUBLIC
    # Add your SDK include paths here
)

# --- 3c. Compile definitions ---

target_compile_definitions(el2go_csr_board_sdk PUBLIC
    # Add your board/chip-specific defines here
)

# --- 3d. Linker script ---

set(EL2GO_LINKER_SCRIPT 
    # add your linker script here
    # e.g.,  ${BOARD_SDK_PATH}/linker/my_board.ld
    PARENT_SCOPE
)
