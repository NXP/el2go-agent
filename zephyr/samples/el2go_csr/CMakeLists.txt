# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(el2go_csr)

# Load common (platform-agnostic) sources and base include dirs.
# EL2GO_CSR_SOURCES_DIR and EL2GO_CSR_APP_SOURCES / EL2GO_CSR_INCLUDE_DIRS
# are set by this include.
include(${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/applications/el2go_csr/sources.cmake)

# --- Common sources and includes ---
target_sources(app PRIVATE ${EL2GO_CSR_APP_SOURCES})
target_include_directories(app PRIVATE
    ${EL2GO_CSR_INCLUDE_DIRS}
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/libs/net_crypto
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/include
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/libs/platforms
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/libs/platforms/els_pkc
)

# --- Zephyr OSAL (always used in a Zephyr build) ---
target_sources(app PRIVATE
    ${EL2GO_CSR_SOURCES_DIR}/osal/zephyr/src/el2go_csr_osal.c
)
target_include_directories(app PRIVATE
    ${EL2GO_CSR_SOURCES_DIR}/osal/zephyr/inc
)

# --- PAL board sources -- selected by SoC Kconfig (Zephyr-idiomatic) ---
# Each entry maps a CONFIG_SOC_SERIES_* symbol to the matching pal/boards/ directory.
# To add support for a new SoC family, append a new target_sources_ifdef block and
# provide the corresponding pal/boards/<name>/ implementation directory.

set(EL2GO_CSR_PAL_DIR ${EL2GO_CSR_SOURCES_DIR}/pal/boards)

# Expose board-specific PAL include dir globally so the mbedTLS library
# (a separate CMake target) can resolve the user config header specified via
# CONFIG_MBEDTLS_USER_CONFIG_FILE.
if(CONFIG_SOC_SERIES_RW6XX)
    zephyr_include_directories(${EL2GO_CSR_PAL_DIR}/rw612/inc)
endif()

# RW6xx family (RW610, RW612, ...)
target_sources_ifdef(CONFIG_SOC_SERIES_RW6XX app PRIVATE
    ${EL2GO_CSR_PAL_DIR}/rw612/el2go_csr_platform.c
    ${EL2GO_CSR_SOURCES_DIR}/pal/zephyr/rw612/el2go_csr_zephyr_memory.c
    ${EL2GO_CSR_PAL_DIR}/rw612/el2go_csr_integrity_verifier.c
    ${EL2GO_CSR_PAL_DIR}/rw612/el2go_csr_challenge.c
    ${EL2GO_CSR_PAL_DIR}/rw612/el2go_csr_psa_key.c
    ${EL2GO_CSR_PAL_DIR}/rw612/el2go_csr_pal_util.c
)
target_include_directories_ifdef(CONFIG_SOC_SERIES_RW6XX app PRIVATE
    ${EL2GO_CSR_PAL_DIR}/rw612/inc
)
