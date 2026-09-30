# Copyright 2024-2026 NXP
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(el2go_blob_test)

# TF-M NS interface headers -- only available when building with TF-M
if(CONFIG_BUILD_WITH_TFM)
    zephyr_include_directories(
        $<TARGET_PROPERTY:tfm,TFM_BINARY_DIR>/api_ns/interface/include
    )
endif()

include(${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/tests/el2go_blob_test/sources.cmake)

target_sources(app PRIVATE
    ${EL2GO_BLOB_TEST_SOURCES}
    # Zephyr platform implementation
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/tests/el2go_blob_test/platform/zephyr/el2go_blob_test_platform.c
)

zephyr_include_directories(
    ${EL2GO_BLOB_TEST_INCLUDE_DIRS}
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/tests/el2go_blob_test/platform/zephyr
)

# When CONFIG_SECURE_STORAGE is enabled, compile the strong secure storage init
# implementation that overrides the __weak no-op stub.
if(CONFIG_SECURE_STORAGE)
    target_sources(app PRIVATE
        ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/tests/el2go_blob_test/platform/zephyr/el2go_blob_test_secure_storage.c
    )
endif()

# Optional pre-build step: generate el2go_blob_test_suite_generic.h from RTP JSON
if(CONFIG_RTP_JSON OR DEFINED ENV{CONFIG_RTP_JSON})
    find_package(Python REQUIRED)
    if(CONFIG_RTP_JSON)
        set(RTP_JSON ${CONFIG_RTP_JSON})
    else()
        set(RTP_JSON $ENV{CONFIG_RTP_JSON})
    endif()
    execute_process(
        COMMAND ${Python_EXECUTABLE}
            ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/tests/el2go_blob_test/scripts/el2go_blob_test_pre.py
            ${RTP_JSON}
        OUTPUT_VARIABLE OUTPUT
        COMMAND_ERROR_IS_FATAL ANY
    )
    message(STATUS ${OUTPUT})
endif()
