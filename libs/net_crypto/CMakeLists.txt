# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

# Common source files
set(NET_CRYPTO_SOURCES
    net_crypto.c
)

# Create the OBJECT library
add_library(net_crypto OBJECT ${NET_CRYPTO_SOURCES})

# Set include directories
target_include_directories(net_crypto
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
    PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/priv
        ${CMAKE_SOURCE_DIR}/libs/osal/include
)

# Add crypto backend sources if backend is specified
if(CRYPTO_BACKEND)
    if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/${CRYPTO_BACKEND})
        add_subdirectory(${CRYPTO_BACKEND})
        message(STATUS "Building net_crypto with ${CRYPTO_BACKEND} backend")
    else()
        message(WARNING "Crypto backend '${CRYPTO_BACKEND}' not found, using weak stubs only")
    endif()
else()
    message(STATUS "Building net_crypto with weak stubs only")
endif()
