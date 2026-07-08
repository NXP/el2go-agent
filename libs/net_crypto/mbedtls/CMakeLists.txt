# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

include(add_target_sources)

if(BUILD_ZEPHYR)
    if(CONFIG_MBEDTLS_VERSION_4_x)
        set(MBEDTLS_VERSION_MAJOR 4)
    else()
        message(FATAL_ERROR
            "Unsupported mbedTLS version for Zephyr build. "
            "Only mbedTLS 4.x is supported (CONFIG_MBEDTLS_VERSION_4_x).")
    endif()
    set(MBEDTLS_EXTRA_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/port/net_zephyr.c)
    set(MBEDTLS_EXTRA_DIRS
        ${CMAKE_CURRENT_SOURCE_DIR}/port
        ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/libs/platforms
        ${ZEPHYR_NXP_IOT_AGENT_MODULE_DIR}/libs/net_crypto
    )
    set(MBEDTLS_LIBS "")
    set(mbedtls_INCLUDE_DIRS "")
    set(mbedtls_LIBRARY_DIRS "")
else()
    include(FindPkgConfig)
    find_package(PkgConfig QUIET REQUIRED)
    pkg_check_modules(mbedtls REQUIRED mbedtls>=2)

    if(NOT mbedtls_FOUND)
        message(FATAL_ERROR "MbedTLS not available")
    endif()

    if(DEFINED MBEDTLS_VERSION)
        message(STATUS "Using manually specified MbedTLS version: ${MBEDTLS_VERSION}")
        set(mbedtls_VERSION ${MBEDTLS_VERSION})
    else()
        message(STATUS "Detected MbedTLS version: ${mbedtls_VERSION}")
    endif()

    string(REGEX MATCH "^([0-9]+)" MBEDTLS_VERSION_MAJOR ${mbedtls_VERSION})
    message(STATUS "MbedTLS major version: ${MBEDTLS_VERSION_MAJOR}")

    if(MBEDTLS_VERSION_MAJOR LESS 2 OR MBEDTLS_VERSION_MAJOR GREATER 4)
        message(FATAL_ERROR
            "Unsupported MbedTLS version: ${MBEDTLS_VERSION_MAJOR} (supported: 2, 3, 4)")
    endif()

    set(MBEDTLS_EXTRA_SOURCES "")
    set(MBEDTLS_EXTRA_DIRS
        ${CMAKE_SOURCE_DIR}/libs/platforms
        ${CMAKE_SOURCE_DIR}/libs/net_crypto
    )

    if(mbedtls_STATIC_LIBRARIES)
        set(MBEDTLS_LIBS ${mbedtls_STATIC_LIBRARIES})
    else()
        message(WARNING "mbedtls libraries not set by pkg-config, using standard names")
        set(MBEDTLS_LIBS mbedtls mbedx509 mbedcrypto)
    endif()

    message(STATUS "MbedTLS include dirs: ${mbedtls_INCLUDE_DIRS}")
    message(STATUS "MbedTLS library dirs: ${mbedtls_LIBRARY_DIRS}")
    message(STATUS "MbedTLS libraries:    ${MBEDTLS_LIBS}")
endif()

set(MBEDTLS_COMPAT_SOURCES "")

# Add common compatibility layer for v2 and v3
if(MBEDTLS_VERSION_MAJOR LESS 4)
    list(APPEND MBEDTLS_COMPAT_SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls_compat_v2_v3_common.c
    )
endif()

# Add version-specific compatibility layer if the file exists.
# This handles v2, v3, v4 and any future major version uniformly.
set(VERSION_SPECIFIC_FILE
    ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls_compat_v${MBEDTLS_VERSION_MAJOR}.c)
if(EXISTS ${VERSION_SPECIFIC_FILE})
    list(APPEND MBEDTLS_COMPAT_SOURCES ${VERSION_SPECIFIC_FILE})
endif()

message(STATUS "Using mbedTLS ${MBEDTLS_VERSION_MAJOR}.x compatibility layer")
message(STATUS "Compatibility sources: ${MBEDTLS_COMPAT_SOURCES}")

add_private_sources(net_crypto
    ${CMAKE_CURRENT_SOURCE_DIR}/net_crypto_mbedtls.c
    ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls_mapping.c
    ${MBEDTLS_COMPAT_SOURCES}
    ${MBEDTLS_EXTRA_SOURCES}
)

add_private_directories(net_crypto
    ${CMAKE_CURRENT_SOURCE_DIR}
)

add_public_directories(net_crypto
    ${mbedtls_INCLUDE_DIRS}
    ${MBEDTLS_EXTRA_DIRS}
)

if(mbedtls_LIBRARY_DIRS)
    target_link_directories(net_crypto PUBLIC ${mbedtls_LIBRARY_DIRS})
endif()

add_link_libraries(net_crypto PUBLIC ${MBEDTLS_LIBS})

if(MBEDTLS_VERSION_MAJOR EQUAL 3)
    add_private_definitions(net_crypto MBEDTLS_USE_PSA_CRYPTO)
    message(STATUS "Enabled MBEDTLS_USE_PSA_CRYPTO for mbedTLS 3.x")
endif()
