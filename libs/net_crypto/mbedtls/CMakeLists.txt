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
        ${PROJECT_ROOT}/include
        ${PROJECT_ROOT}/priv
        ${PROJECT_ROOT}/libs/platforms
        ${PROJECT_ROOT}/libs/net_crypto
        ${PROJECT_ROOT}/libs/osal/include
    )
    set(MBEDTLS_LIBS "")
    set(mbedtls_INCLUDE_DIRS "")
    set(mbedtls_LIBRARY_DIRS "")
    # TLS sources only when networking stack is present
    if(CONFIG_NETWORKING)
        set(MBEDTLS_TLS_ENABLED TRUE)
        set(MBEDTLS_TLS_SOURCES
            ${CMAKE_CURRENT_SOURCE_DIR}/net_crypto_mbedtls_tls.c
            ${CMAKE_CURRENT_SOURCE_DIR}/port/net_zephyr.c
        )
    else()
        set(MBEDTLS_TLS_ENABLED FALSE)
        set(MBEDTLS_TLS_SOURCES "")
    endif()
    # CSR sources only when X.509 CSR write support is enabled
    if(CONFIG_MBEDTLS_PEM_WRITE_C)
        set(MBEDTLS_CSR_ENABLED TRUE)
    else()
        set(MBEDTLS_CSR_ENABLED FALSE)
    endif()
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

    # On Linux the networking stack is always present
    set(MBEDTLS_TLS_ENABLED TRUE)
    set(MBEDTLS_TLS_SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/net_crypto_mbedtls_tls.c
    )
    # On Linux CSR support is always compiled (full mbedTLS available)
    set(MBEDTLS_CSR_ENABLED TRUE)
endif()

# ============================================================================
# Compatibility layer sources
# ============================================================================

# RNG compat: always required (used by crypto, tls, and csr layers).
# v2 and v3 share one implementation file; v4 uses a PSA stub.
if(MBEDTLS_VERSION_MAJOR LESS 4)
    set(MBEDTLS_COMPAT_RNG_SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/compat/mbedtls_compat_rng_v2_v3.c)
else()
    set(MBEDTLS_COMPAT_RNG_SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/compat/mbedtls_compat_rng_v4.c)
endif()

# Crypto compat: always required
set(MBEDTLS_COMPAT_CRYPTO_SOURCES "")
if(MBEDTLS_VERSION_MAJOR LESS 4)
    list(APPEND MBEDTLS_COMPAT_CRYPTO_SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/compat/crypto/mbedtls_compat_crypto_v2_v3.c)
endif()
set(CRYPTO_VERSION_FILE
    ${CMAKE_CURRENT_SOURCE_DIR}/compat/crypto/mbedtls_compat_crypto_v${MBEDTLS_VERSION_MAJOR}.c)
if(EXISTS ${CRYPTO_VERSION_FILE})
    list(APPEND MBEDTLS_COMPAT_CRYPTO_SOURCES ${CRYPTO_VERSION_FILE})
else()
    message(FATAL_ERROR "No crypto compat file for mbedTLS ${MBEDTLS_VERSION_MAJOR}.x: ${CRYPTO_VERSION_FILE}")
endif()

# TLS compat: only when TLS layer is enabled
set(MBEDTLS_COMPAT_TLS_SOURCES "")
if(MBEDTLS_TLS_ENABLED)
    if(MBEDTLS_VERSION_MAJOR LESS 4)
        list(APPEND MBEDTLS_COMPAT_TLS_SOURCES
            ${CMAKE_CURRENT_SOURCE_DIR}/compat/tls/mbedtls_compat_tls_v2_v3.c)
    endif()
    set(TLS_VERSION_FILE
        ${CMAKE_CURRENT_SOURCE_DIR}/compat/tls/mbedtls_compat_tls_v${MBEDTLS_VERSION_MAJOR}.c)
    if(EXISTS ${TLS_VERSION_FILE})
        list(APPEND MBEDTLS_COMPAT_TLS_SOURCES ${TLS_VERSION_FILE})
    else()
        message(FATAL_ERROR "No TLS compat file for mbedTLS ${MBEDTLS_VERSION_MAJOR}.x: ${TLS_VERSION_FILE}")
    endif()
endif()

# CSR compat: only when CSR write support is available
set(MBEDTLS_COMPAT_CSR_SOURCES "")
if(MBEDTLS_CSR_ENABLED)
    if(MBEDTLS_VERSION_MAJOR LESS 4)
        list(APPEND MBEDTLS_COMPAT_CSR_SOURCES
            ${CMAKE_CURRENT_SOURCE_DIR}/compat/csr/mbedtls_compat_csr_v2_v3.c)
    endif()
    set(CSR_VERSION_FILE
        ${CMAKE_CURRENT_SOURCE_DIR}/compat/csr/mbedtls_compat_csr_v${MBEDTLS_VERSION_MAJOR}.c)
    if(EXISTS ${CSR_VERSION_FILE})
        list(APPEND MBEDTLS_COMPAT_CSR_SOURCES ${CSR_VERSION_FILE})
    endif()
    list(APPEND MBEDTLS_COMPAT_CSR_SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/net_crypto_mbedtls_crypto_csr.c)
endif()

set(MBEDTLS_COMPAT_SOURCES
    ${MBEDTLS_COMPAT_RNG_SOURCES}
    ${MBEDTLS_COMPAT_TLS_SOURCES}
    ${MBEDTLS_COMPAT_CRYPTO_SOURCES}
    ${MBEDTLS_COMPAT_CSR_SOURCES}
)

message(STATUS "Using mbedTLS ${MBEDTLS_VERSION_MAJOR}.x compatibility layer")
message(STATUS "Compatibility sources: ${MBEDTLS_COMPAT_SOURCES}")

# mapping/mbedtls_mapping.c uses TLS compat symbols - only include when TLS is enabled
if(MBEDTLS_TLS_ENABLED)
    set(MBEDTLS_MAPPING_SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/mapping/mbedtls_mapping.c)
else()
    set(MBEDTLS_MAPPING_SOURCES "")
endif()

add_private_sources(net_crypto
    ${CMAKE_CURRENT_SOURCE_DIR}/net_crypto_mbedtls_crypto.c
    ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls_debug.c
    ${MBEDTLS_MAPPING_SOURCES}
    ${MBEDTLS_COMPAT_SOURCES}
    ${MBEDTLS_TLS_SOURCES}
)

add_private_directories(net_crypto
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/compat
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

# Configurable SSL read timeout passed to mbedtls_ssl_conf_read_timeout().
# Override at cmake time with -DNET_CRYPTO_SSL_READ_TIMEOUT_MS=<value>.
if(NOT NET_CRYPTO_SSL_READ_TIMEOUT_MS)
    set(NET_CRYPTO_SSL_READ_TIMEOUT_MS 60000)
endif()
message(STATUS "NET_CRYPTO_SSL_READ_TIMEOUT_MS: ${NET_CRYPTO_SSL_READ_TIMEOUT_MS}")
add_private_definitions(net_crypto
    NET_CRYPTO_SSL_READ_TIMEOUT_MS=${NET_CRYPTO_SSL_READ_TIMEOUT_MS}U)

# Enable mbedTLS internal debug output. On Linux, pass
# -DEL2GO_MBEDTLS_DEBUG_ENABLE=ON; on Zephyr, use CONFIG_EL2GO_MBEDTLS_DEBUG_ENABLE.
option(EL2GO_MBEDTLS_DEBUG_ENABLE "Enable mbedTLS internal debug output" OFF)

if(EL2GO_MBEDTLS_DEBUG_ENABLE)
    message(STATUS "EL2GO_MBEDTLS_DEBUG_ENABLE: ON")
    add_private_definitions(net_crypto EL2GO_MBEDTLS_DEBUG_ENABLE)
endif()
