# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#
# ==============================================================================
#          EL2GO CSR Application - Standalone Build for non-NXP MCUs
# ==============================================================================

cmake_minimum_required(VERSION 3.15)

project(el2go_csr
    LANGUAGES C ASM
    VERSION 1.0.0
)

# --- Options --- 

set(EL2GO_CSR_BOARD "" CACHE STRING "Target board")
set(EL2GO_CSR_OS "baremetal" CACHE STRING "Target OS: baremetal, zephyr")
set(EL2GO_CSR_MBEDTLS_PATH "" CACHE PATH "Path to MbedTLS (required)")
set(EL2GO_CSR_LOG_LEVEL "LOG_INFO" CACHE STRING "Log level")

if(NOT EL2GO_CSR_BOARD)
    message(FATAL_ERROR "EL2GO_CSR_BOARD not specified!\n\n")
endif()

if(NOT EL2GO_CSR_MBEDTLS_PATH)
    message(FATAL_ERROR "EL2GO_CSR_MBEDTLS_PATH not specified!\n\n")
endif()


# --- Directories ---

set(ROOT ${CMAKE_CURRENT_SOURCE_DIR})
set(APP_DIR ${ROOT}/app)
set(COMMON_DIR ${ROOT}/common)
set(OSAL_DIR ${ROOT}/osal)
set(PAL_DIR ${ROOT}/pal)
set(PORT_DIR ${ROOT}/port)
set(BOARD_DIR ${PAL_DIR}/boards/${EL2GO_CSR_BOARD})
set(OSAL_OS_DIR ${OSAL_DIR}/${EL2GO_CSR_OS})

if(NOT EXISTS "${BOARD_DIR}")
    message(FATAL_ERROR "Board '${EL2GO_CSR_BOARD}' not found at: ${BOARD_DIR}")
endif()

if(NOT EXISTS "${BOARD_DIR}/CMakeLists.txt")
    message(FATAL_ERROR "Board '${EL2GO_CSR_BOARD}' is missing a CMakeLists.txt at: ${BOARD_DIR}")
endif()

if(NOT EXISTS "${OSAL_OS_DIR}")
    message(FATAL_ERROR "OS '${EL2GO_CSR_OS}' not found. Available: baremetal, zephyr")
endif()

if(NOT EXISTS "${EL2GO_CSR_MBEDTLS_PATH}")
    message(FATAL_ERROR "MbedTLS not found at: ${EL2GO_CSR_MBEDTLS_PATH}")
endif()

# ==============================================================================
#  Board-specific setup
#  Each board CMakeLists.txt must provide:
#    - el2go_csr_board_sdk   : INTERFACE or STATIC target with SDK deps
#    - EL2GO_CSR_BOARD_SOURCES (PARENT_SCOPE) : list of board .c files
#    - EL2GO_CSR_BOARD_INCLUDE_DIRS (PARENT_SCOPE) : board-specific include dirs
# ==============================================================================

add_subdirectory(${BOARD_DIR} ${CMAKE_BINARY_DIR}/board)

if(NOT TARGET el2go_csr_board_sdk)
    message(FATAL_ERROR "Board '${EL2GO_CSR_BOARD}' CMakeLists.txt must define an interface target.")
endif()


# --- Library Target ---

add_library(el2go_csr_lib STATIC)
target_compile_features(el2go_csr_lib PUBLIC c_std_99)

target_sources(el2go_csr_lib PRIVATE
    # App
    ${APP_DIR}/src/el2go_csr_tlv_parser.c
    # Common
    ${COMMON_DIR}/src/csr_util.c
    # OSAL
    ${OSAL_OS_DIR}/src/el2go_csr_osal.c
    # Board
    ${EL2GO_CSR_BOARD_SOURCES}
)

target_include_directories(el2go_csr_lib PUBLIC
    ${APP_DIR}/inc
    ${COMMON_DIR}/inc
    ${OSAL_DIR}/inc
    ${OSAL_OS_DIR}/inc
    ${PAL_DIR}/inc
    ${PORT_DIR}
    ${EL2GO_CSR_MBEDTLS_PATH}/include
    ${EL2GO_CSR_BOARD_INCLUDE_DIRS}
)

target_compile_definitions(el2go_csr_lib PUBLIC
    MBEDTLS_CONFIG_FILE="${PORT_DIR}/el2go_csr_mbedtls_user_config.h"
)

target_link_libraries(el2go_csr_lib PUBLIC
    el2go_csr_board_sdk
    mbedcrypto
    mbedtls
    mbedx509
)
