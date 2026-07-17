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
# Default PLATFORM for Zephyr — ELS PKC for RW6xx family.
# Can be overridden by the application CMake before including this file.
# ---------------------------------------------------------------------------
if(NOT DEFINED PLATFORM)
    set(PLATFORM els_pkc)
endif()

# ---------------------------------------------------------------------------
# Default CRYPTO_BACKEND for Zephyr — mbedTLS is provided by the Zephyr SDK.
# Can be overridden by the application CMake before including this file.
# ---------------------------------------------------------------------------
if(NOT DEFINED CRYPTO_BACKEND)
    set(CRYPTO_BACKEND mbedtls)
endif()

# ---------------------------------------------------------------------------
# Shared public include root — resolves <ota/...> and <fwual/...> headers.
# ---------------------------------------------------------------------------
if(CONFIG_EL2GO_OTA_LIBRARY_SOURCES OR CONFIG_EL2GO_OTA_FWUAL_LIBRARY_SOURCES)
    zephyr_include_directories(${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/include)
endif()

# ---------------------------------------------------------------------------
# OSAL — OS Abstraction Layer (alloc, print, file, uuid)
# Must come before any library that depends on it.
# ---------------------------------------------------------------------------
if(CONFIG_EL2GO_OTA_LIBRARY_SOURCES OR CONFIG_EL2GO_OTA_FWUAL_LIBRARY_SOURCES)
    add_subdirectory(
        ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/libs/osal/zephyr
        ${CMAKE_CURRENT_BINARY_DIR}/osal
    )
endif()

# ---------------------------------------------------------------------------
# FWUAL — Firmware Update Abstraction Layer
# ---------------------------------------------------------------------------
if(CONFIG_EL2GO_OTA_FWUAL_LIBRARY_SOURCES)
    add_subdirectory(
        ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/libs/fwual
        ${CMAKE_CURRENT_BINARY_DIR}/fwual
    )
endif()

# ---------------------------------------------------------------------------
# net_crypto — mbedTLS backend for mTLS
# Must come before el2go_ota_lib (it's a dependency).
# ---------------------------------------------------------------------------
if(CONFIG_EL2GO_OTA_LIBRARY_SOURCES AND CONFIG_MBEDTLS)
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
