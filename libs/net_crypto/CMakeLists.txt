# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

include(add_target_sources)

declare_library(net_crypto)

add_private_sources(net_crypto
    net_crypto.c
)

add_public_directories(net_crypto
    ${CMAKE_CURRENT_SOURCE_DIR}
)

add_private_directories(net_crypto
    ${PROJECT_ROOT}/include
    ${PROJECT_ROOT}/priv
    ${PROJECT_ROOT}/libs/osal/include
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