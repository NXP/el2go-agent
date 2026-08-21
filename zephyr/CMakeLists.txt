# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

set(BUILD_ZEPHYR 1)
set(CMAKE_MODULE_PATH
    ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/cmake
    ${CMAKE_MODULE_PATH}
)

# ---------------------------------------------------------------------------
# BUILD_OTA -- OTA is fully implemented on Zephyr; always enable it.
# ---------------------------------------------------------------------------
set(BUILD_OTA ON)

# ---------------------------------------------------------------------------
# Default PLATFORM for Zephyr -- ELS PKC for RW6xx family.
# Can be overridden by the application CMake before including this file.
# ---------------------------------------------------------------------------
if(NOT DEFINED PLATFORM)
    set(PLATFORM els_pkc)
endif()

# ---------------------------------------------------------------------------
# Default CRYPTO_BACKEND for Zephyr -- mbedTLS is provided by the Zephyr SDK.
# Can be overridden by the application CMake before including this file.
# ---------------------------------------------------------------------------
if(NOT DEFINED CRYPTO_BACKEND)
    set(CRYPTO_BACKEND mbedtls)
endif()

# ---------------------------------------------------------------------------
# OS -- identifies the OS backend for subdirectory dispatch (e.g. osal/${OS})
# ---------------------------------------------------------------------------
if(NOT DEFINED OS)
    set(OS zephyr)
endif()

# ---------------------------------------------------------------------------
# PROJECT_ROOT -- absolute path to the repository root, used by all
# CMakeLists.txt files to reference headers and sources without ../../..
# ---------------------------------------------------------------------------
if(NOT DEFINED PROJECT_ROOT)
    set(PROJECT_ROOT ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR})
endif()

# ---------------------------------------------------------------------------
# Backend selection (Zephyr: resolved from Kconfig symbols)
# Each OS-specific CMake sets these variables in its own way.
# On Linux no backend directories exist yet; weak symbols are used by default.
# ---------------------------------------------------------------------------
if(CONFIG_EL2GO_NETWORK_BACKEND_WIFI)
    set(NET_BACKEND wifi)
else()
    set(NET_BACKEND default)
endif()

if(CONFIG_EL2GO_TIME_BACKEND_SNTP)
    set(TIME_BACKEND sntp)
else()
    set(TIME_BACKEND default)
endif()

set(SYSTEM_BACKEND default)

if(CONFIG_EL2GO_OTA_DIAG_BACKEND_RINGBUF)
    set(DIAG_BACKEND ringbuf)
else()
    set(DIAG_BACKEND console)
endif()

if(CONFIG_EL2GO_OTA_PERSIST_BACKEND_NVS)
    set(PERSIST_BACKEND nvs)
else()
    set(PERSIST_BACKEND default)
endif()

if(CONFIG_EL2GO_OTA_EVENT_BACKEND_NETMGMT)
    set(EVENT_BACKEND netmgmt)
else()
    set(EVENT_BACKEND default)
endif()

# ---------------------------------------------------------------------------
# Shared public include root -- resolves <ota/...> and <fwual/...> headers.
# ---------------------------------------------------------------------------
if(CONFIG_EL2GO_OTA_LIBRARY_SOURCES OR CONFIG_EL2GO_OTA_FWUAL_LIBRARY_SOURCES)
    zephyr_include_directories(${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/include)
endif()

# ---------------------------------------------------------------------------
# OSAL -- OS Abstraction Layer (alloc, print, file, uuid)
# Must come before any library that depends on it.
# ---------------------------------------------------------------------------
if(CONFIG_EL2GO_OTA_LIBRARY_SOURCES OR CONFIG_EL2GO_OTA_FWUAL_LIBRARY_SOURCES)
    add_subdirectory(
        ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/libs/osal/zephyr
        ${CMAKE_CURRENT_BINARY_DIR}/osal
    )
endif()

# ---------------------------------------------------------------------------
# FWUAL -- Firmware Update Abstraction Layer
# ---------------------------------------------------------------------------
if(CONFIG_EL2GO_OTA_FWUAL_LIBRARY_SOURCES)
    add_subdirectory(
        ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/libs/fwual
        ${CMAKE_CURRENT_BINARY_DIR}/fwual
    )
endif()

# ---------------------------------------------------------------------------
# net_crypto -- mbedTLS crypto abstraction layer.
# Only built when explicitly requested via EL2GO_NET_CRYPTO_SOURCES.
# This prevents it from being compiled into child images (e.g. MCUboot) that
# have CONFIG_MBEDTLS but a minimal config lacking X.509 write and PK write
# support. Must come before el2go_ota_lib (it is a dependency).
# ---------------------------------------------------------------------------
if(CONFIG_EL2GO_NET_CRYPTO_SOURCES)
    add_subdirectory(
        ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/libs/net_crypto
        ${CMAKE_CURRENT_BINARY_DIR}/net_crypto
    )
endif()

# ---------------------------------------------------------------------------
# Platform backend — PSA crypto init, hardware-specific glue
# Must come before el2go_ota_lib (it's a dependency).
# ---------------------------------------------------------------------------
if(CONFIG_EL2GO_OTA_PLATFORM_SOURCES)
    add_subdirectory(
        ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/libs/platforms
        ${CMAKE_CURRENT_BINARY_DIR}/platforms
    )
endif()

# ---------------------------------------------------------------------------
# Protobuf (nanopb runtime + OTA generated files)
# Must come before el2go_ota_lib which uses the generated .pb.h headers.
# ---------------------------------------------------------------------------
if(CONFIG_EL2GO_OTA_LIBRARY_SOURCES)
    add_subdirectory(
        ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/libs/protobuf
        ${CMAKE_CURRENT_BINARY_DIR}/protobuf
    )
endif()

# ---------------------------------------------------------------------------
# EL2GO OTA Library (TLS, credential, OTA logic)
# Depends on: net_crypto, el2go_platform, osal
# ---------------------------------------------------------------------------
if(CONFIG_EL2GO_OTA_LIBRARY_SOURCES)
    add_subdirectory(
        ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/libs/el2go_ota_lib
        ${CMAKE_CURRENT_BINARY_DIR}/el2go_ota_lib
    )
endif()

# ---------------------------------------------------------------------------
# Cross-agent application common (network, system, time)
# ---------------------------------------------------------------------------
if(CONFIG_EL2GO_NETWORK_SOURCES)
    zephyr_include_directories(${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/applications/common/network)
endif()

if(CONFIG_EL2GO_SYSTEM_SOURCES)
    zephyr_include_directories(${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/applications/common/system)
endif()

if(CONFIG_EL2GO_TIME_SOURCES)
    zephyr_include_directories(${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/applications/common/time)
endif()

if(CONFIG_EL2GO_NETWORK_SOURCES OR CONFIG_EL2GO_SYSTEM_SOURCES OR
   CONFIG_EL2GO_TIME_SOURCES)
    add_subdirectory(
        ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/applications/common
        ${CMAKE_CURRENT_BINARY_DIR}/app_common
    )
endif()

# ---------------------------------------------------------------------------
# OTA-agent application common (diag, persist, event)
# ---------------------------------------------------------------------------
if(CONFIG_EL2GO_OTA_DIAG_SOURCES OR CONFIG_EL2GO_OTA_PERSIST_SOURCES OR
   CONFIG_EL2GO_OTA_EVENT_SOURCES)
    zephyr_include_directories(
        ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/applications/ota_agents/common/diag
        ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/applications/ota_agents/common/persist
        ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/applications/ota_agents/common/event
    )
    add_subdirectory(
        ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/applications/ota_agents/common
        ${CMAKE_CURRENT_BINARY_DIR}/ota_app_common
    )
endif()
