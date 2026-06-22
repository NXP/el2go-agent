# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

# MbedTLS 2.x does not export a cmake configuration
include(FindPkgConfig)

find_package(PkgConfig QUIET REQUIRED)
pkg_check_modules(mbedtls REQUIRED mbedtls>=2)

if(NOT ${mbedtls_FOUND})
    message(FATAL_ERROR "MbedTLS not available")
endif()

# Allow manual override of MbedTLS version detection
if(DEFINED MBEDTLS_VERSION)
    message(STATUS "Using manually specified MbedTLS version: ${MBEDTLS_VERSION}")
    set(mbedtls_VERSION ${MBEDTLS_VERSION})
else()
    message(STATUS "Detected MbedTLS version: ${mbedtls_VERSION}")
endif()

# Extract major version number
string(REGEX MATCH "^([0-9]+)" MBEDTLS_VERSION_MAJOR ${mbedtls_VERSION})
message(STATUS "MbedTLS major version: ${MBEDTLS_VERSION_MAJOR}")

# Validate if version is supported
if(MBEDTLS_VERSION_MAJOR LESS 2 OR MBEDTLS_VERSION_MAJOR GREATER 4)
    message(FATAL_ERROR "Unsupported MbedTLS version: ${MBEDTLS_VERSION_MAJOR} (supported: 2, 3, 4)")
endif()

# Determine which compatibility layer files to compile based on version
set(MBEDTLS_COMPAT_SOURCES "")

# Add common compatibility layer for v2 and v3
if(MBEDTLS_VERSION_MAJOR LESS 4)
    list(APPEND MBEDTLS_COMPAT_SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls_compat_v2_v3_common.c
    )
endif()

# Add version-specific compatibility layer (if it exists)
set(VERSION_SPECIFIC_FILE ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls_compat_v${MBEDTLS_VERSION_MAJOR}.c)
if(EXISTS ${VERSION_SPECIFIC_FILE})
    list(APPEND MBEDTLS_COMPAT_SOURCES ${VERSION_SPECIFIC_FILE})
endif()

message(STATUS "Using mbedTLS ${MBEDTLS_VERSION_MAJOR}.x compatibility layer")
message(STATUS "Compatibility sources: ${MBEDTLS_COMPAT_SOURCES}")

# Add mbedTLS backend sources directly to parent target
target_sources(net_crypto PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/net_crypto_mbedtls.c
    ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls_mapping.c
    ${MBEDTLS_COMPAT_SOURCES}
)

# Add include paths - PUBLIC so they propagate to consumers
target_include_directories(net_crypto PUBLIC
    ${CMAKE_SOURCE_DIR}/libs/platforms
    ${CMAKE_SOURCE_DIR}/libs/net_crypto
    ${mbedtls_INCLUDE_DIRS}
)

# Add library directories - PUBLIC so they propagate to consumers
if(mbedtls_LIBRARY_DIRS)
    target_link_directories(net_crypto PUBLIC ${mbedtls_LIBRARY_DIRS})
endif()

# Use static library names
set(MBEDTLS_LIBS "")
if(mbedtls_STATIC_LIBRARIES)
    set(MBEDTLS_LIBS ${mbedtls_STATIC_LIBRARIES})
else()
    message(WARNING "mbedtls libraries not set by pkg-config, using standard library names")
    set(MBEDTLS_LIBS mbedtls mbedx509 mbedcrypto)
endif()

# Link mbedTLS libraries - PUBLIC so they propagate to all consumers
target_link_libraries(net_crypto PUBLIC ${MBEDTLS_LIBS})

# Define MBEDTLS_USE_PSA_CRYPTO - only for v3 and v4
if(MBEDTLS_VERSION_MAJOR EQUAL 3)
    target_compile_definitions(net_crypto PUBLIC MBEDTLS_USE_PSA_CRYPTO)
    message(STATUS "Enabled MBEDTLS_USE_PSA_CRYPTO for mbedTLS ${MBEDTLS_VERSION_MAJOR}.x")
endif()

message(STATUS "MbedTLS include dirs: ${mbedtls_INCLUDE_DIRS}")
message(STATUS "MbedTLS library dirs: ${mbedtls_LIBRARY_DIRS}")
message(STATUS "MbedTLS libraries: ${MBEDTLS_LIBS}")
