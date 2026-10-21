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

if(CONFIG_EL2GO_TFM_LEGACY_CRYPTO_ENABLE)
    set_property(TARGET zephyr_property_target
        APPEND PROPERTY TFM_CMAKE_OPTIONS
        -DTFM_TF_PSA_CRYPTO_PLATFORM_EXTRA_CONFIG_PATH=${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/zephyr/common/mbedcrypto_extra_config.h
    )
endif()

if(CONFIG_EL2GO_TFM_DATA_IMPORT_REGION)
    set_property(TARGET zephyr_property_target
        APPEND PROPERTY TFM_CMAKE_OPTIONS
        -DUSE_TFM_EL2GO_DATA_IMPORT_REGION=ON
    )
endif()

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
# EL2GO library logging (EL2GO_DBG_PRINTF calls across libs.
# ---------------------------------------------------------------------------
if(CONFIG_EL2GO_LIB_LOG_LEVEL GREATER 0)
    zephyr_compile_definitions(ENABLE_TRACE)
    zephyr_compile_definitions(TRACE_LEVEL=${CONFIG_EL2GO_LIB_LOG_LEVEL})
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

if(CONFIG_EL2GO_RTP_PSA_BACKEND_TFM)
    set(NXP_IOT_AGENT_HAVE_PSA_IMPL_TFM 1)
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
    # Forward the Kconfig SSL read timeout to the net_crypto cmake layer so
    # mbedtls/CMakeLists.txt picks it up via -DNET_CRYPTO_SSL_READ_TIMEOUT_MS.
    set(NET_CRYPTO_SSL_READ_TIMEOUT_MS ${CONFIG_EL2GO_NET_CRYPTO_SSL_READ_TIMEOUT_MS})
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
    add_subdirectory(
        ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/applications/ota_agents/common
        ${CMAKE_CURRENT_BINARY_DIR}/ota_app_common
    )
endif()

# ---------------------------------------------------------------------------
# RTP agent (includes, libraries, compile definitions)
# ---------------------------------------------------------------------------
if(CONFIG_EL2GO_RTP_AGENT)
    # Protobuf (nanopb runtime + RTP generated files) -- shared with OTA if already added.
    if(NOT TARGET el2go_protobuf)
        add_subdirectory(
            ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/libs/protobuf
            ${CMAKE_CURRENT_BINARY_DIR}/protobuf_rtp
        )
    endif()

    # Common libs (server connection, service, certificates).
    add_subdirectory(
        ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/libs/common
        ${CMAKE_CURRENT_BINARY_DIR}/common_rtp
    )

    # Network backend -- shared with OTA if already added via app_common.
    if(NOT TARGET el2go_app_net)
        add_subdirectory(
            ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/applications/common/network
            ${CMAKE_CURRENT_BINARY_DIR}/app_net
        )
    endif()

    # MQTT transport layer for the RTP agent.
    add_subdirectory(
        ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/applications/common/mqtt
        ${CMAKE_CURRENT_BINARY_DIR}/el2go_mqtt
    )

    # OSAL -- shared with OTA if already added; guard against duplicate targets.
    if(NOT TARGET osal)
        add_subdirectory(
            ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/libs/osal/zephyr
            ${CMAKE_CURRENT_BINARY_DIR}/osal
        )
    endif()

    # Platform backend -- must come before el2go_rtp_lib which links against el2go_platform.
    if(NOT TARGET el2go_platform)
        add_subdirectory(
            ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/libs/platforms
            ${CMAKE_CURRENT_BINARY_DIR}/platforms_rtp
        )
    endif()

    # Core RTP library.
    add_subdirectory(
        ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/libs/el2go_rtp_lib
        ${CMAKE_CURRENT_BINARY_DIR}/el2go_rtp_lib
    )

    # PSA keystore.
    add_subdirectory(
        ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/libs/keystores
        ${CMAKE_CURRENT_BINARY_DIR}/keystores
    )

    # Datastores.
    add_subdirectory(
        ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/libs/datastores
        ${CMAKE_CURRENT_BINARY_DIR}/datastores
    )

    # net_crypto -- shared with OTA if already added via CONFIG_EL2GO_NET_CRYPTO_SOURCES.
    if(CONFIG_MBEDTLS AND NOT TARGET net_crypto)
        add_subdirectory(
            ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/libs/net_crypto
            ${CMAKE_CURRENT_BINARY_DIR}/net_crypto_rtp
        )
    endif()

    # Compile definitions.
    zephyr_compile_definitions(
        AX_EMBEDDED=1
        PB_FIELD_32BIT
        USE_RTOS=1
    )

    if(CONFIG_EL2GO_RTP_PSA_BACKEND_TFM)
        zephyr_compile_definitions(NXP_IOT_AGENT_HAVE_PSA_IMPL_TFM=1)
    else()
        zephyr_compile_definitions(
            NXP_IOT_AGENT_HAVE_PSA_IMPL_ELS_PKC=1
            MCUXCLPSADRIVER_KEY_RECIPE_IMPORT_ENABLE
        )
    endif()

    if(CONFIG_EL2GO_RTP_CLAIMCODE_INJECT)
    set(EL2GO_RTP_CLAIMCODE_FLASH_ADDRESS ${CONFIG_EL2GO_RTP_CLAIMCODE_FLASH_ADDRESS})
    zephyr_compile_definitions(
        EL2GO_RTP_CLAIMCODE_FLASH_ADDRESS=${EL2GO_RTP_CLAIMCODE_FLASH_ADDRESS}
    )
    endif()

    if(CONFIG_EL2GO_TIME_MEASUREMENT)
        zephyr_compile_definitions(EL2GO_TIME_MEASUREMENT_ENABLE=1)
    endif()

    if(CONFIG_EL2GO_RTP_ENABLE_INFO)
        zephyr_compile_definitions(ENABLE_EL2GO_RTP_INFO=1)
    endif()
    if(CONFIG_EL2GO_RTP_ENABLE_WARN)
        zephyr_compile_definitions(ENABLE_EL2GO_RTP_WARN=1)
    endif()
    if(CONFIG_EL2GO_RTP_ENABLE_ERROR)
        zephyr_compile_definitions(ENABLE_EL2GO_RTP_ERROR=1)
    endif()
    if(CONFIG_EL2GO_RTP_ENABLE_DEBUG)
        zephyr_compile_definitions(ENABLE_EL2GO_RTP_DEBUG=1)
    endif()
    if(CONFIG_EL2GO_RTP_ENABLE_TRACE)
        zephyr_compile_definitions(ENABLE_EL2GO_RTP_TRACE=1)
    endif()

endif() # CONFIG_EL2GO_RTP_AGENT

# Possibility to view mbedTLS-only logs
if(CONFIG_EL2GO_MBEDTLS_DEBUG_ENABLE)
    zephyr_compile_definitions(EL2GO_MBEDTLS_DEBUG_ENABLE)
endif()

# Sign image using SPSDK 'nxpimage' tool
if(CONFIG_EL2GO_SIGN_USING_NXPIMAGE OR(DEFINED ENV{CONFIG_EL2GO_SIGN_USING_NXPIMAGE}
    AND "$ENV{CONFIG_EL2GO_SIGN_USING_NXPIMAGE}" STREQUAL "y")
    AND("${BOARD}/${BOARD_QUALIFIERS}" STREQUAL "rd_rw612_bga/rw612/ns"
    OR "${BOARD}/${BOARD_QUALIFIERS}" STREQUAL "frdm_rw612/rw612/ns"))
    include(${CMAKE_CURRENT_LIST_DIR}/sign_s_ns/cmake/sign_s_ns.cmake)
endif()