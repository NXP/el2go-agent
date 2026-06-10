# Copyright 2026 NXP
# SPDX-License-Identifier: Apache-2.0

# This file is the Zephyr module entry point for nxp_iot_agent.
# BUILD_ZEPHYR=1 is set here so that library CMakeLists.txt files
# can dispatch to the correct CMake API via add_target_sources.cmake.

set(BUILD_ZEPHYR 1)
set(CMAKE_MODULE_PATH
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/cmake
    ${CMAKE_MODULE_PATH}
)

# Shared include root for all OTA libraries (fwual/ and ota/ sub-dirs live here).
# Added unconditionally so both libraries resolve their headers correctly
# regardless of which Kconfig combination is selected.
zephyr_include_directories(${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/include)

if(CONFIG_EL2GO_OTA_FWUAL_LIBRARY_SOURCES)
    add_subdirectory(
        ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/libs/fwual
        ${CMAKE_CURRENT_BINARY_DIR}/fwual
    )
endif()

if(CONFIG_EL2GO_OTA_LIBRARY_SOURCES)
    add_subdirectory(
        ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/libs/el2go_ota_lib
        ${CMAKE_CURRENT_BINARY_DIR}/el2go_ota_lib
    )
endif()
