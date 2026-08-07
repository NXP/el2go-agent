# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

cmake_minimum_required(VERSION ${CMAKE_MINIMUM_REQUIRED_VERSION})
project(el2go_unit_tests VERSION 1.0 LANGUAGES C)

# ============================================================================
# Enable CTest for unit tests
# ============================================================================
enable_testing()

# ============================================================================
# Build the unit test framework first
# ============================================================================
add_subdirectory(framework)

# ============================================================================
# Collect test sources from subdirectories
# ============================================================================

# Initialize empty lists
set(PUBLIC_TEST_SOURCES "")
set(INTERNAL_TEST_SOURCES "")

add_subdirectory(osal)

# Collect public RTP tests
add_subdirectory(public_rtp)

# Collect internal RTP tests
add_subdirectory(internal_rtp)

# Collect public datastore tests
add_subdirectory(public_datastore)

# Collect internal datastore tests
add_subdirectory(internal_datastore)

# Collect public keystore tests
add_subdirectory(public_keystore)

# Collect public platform tests
add_subdirectory(public_platform)

# Collect internal platform tests
add_subdirectory(internal_platform)

# Collect internal keystore tests
add_subdirectory(internal_keystore)

# Collect public transport tests
add_subdirectory(public_net_crypto)

# Collect internal transport tests
add_subdirectory(internal_net_crypto)

# Collect public fwual tests
add_subdirectory(public_fwual)

# Collect internal fwual tests
add_subdirectory(internal_fwual)

# Collect public ota_lib tests
add_subdirectory(public_ota_lib)

# Collect internal ota_lib tests
add_subdirectory(internal_ota_lib)

# Collect public ota_agent_core tests
add_subdirectory(public_ota_agent_core)

# Collect internal ota_agent_core tests
add_subdirectory(internal_ota_agent_core)

# Collect public ota_agent_advanced tests
add_subdirectory(public_ota_agent_advanced)

# Collect internal ota_agent_advanced tests
add_subdirectory(internal_ota_agent_advanced)

# ============================================================================
# Test sources organized by type
# ============================================================================

# Public API tests - only test what external users can access
set(PUBLIC_API_TEST_SOURCES
    osal/linux/linux_main.c
    ${PUBLIC_TEST_SOURCES}
)

# Internal/implementation tests - test internal details
set(INTERNAL_API_TEST_SOURCES
    osal/linux/linux_main.c
    ${CMAKE_SOURCE_DIR}/libs/el2go_rtp_lib/el2go_rtp.c
    ${CMAKE_SOURCE_DIR}/libs/el2go_rtp_lib/el2go_rtp_dispatcher.c
    ${CMAKE_SOURCE_DIR}/libs/el2go_rtp_lib/el2go_agent_endpoint.c
    ${CMAKE_SOURCE_DIR}/libs/el2go_rtp_lib/el2go_rtp_status_report.c
    ${INTERNAL_TEST_SOURCES}
)

# Set variables for test definitions
set(PUBLIC_TEST_EXECUTABLE ${PROJECT_NAME}_public)
set(INTERNAL_TEST_EXECUTABLE ${PROJECT_NAME}_internal)

# ============================================================================
# PUBLIC API TEST EXECUTABLE
# ============================================================================

add_executable(${PUBLIC_TEST_EXECUTABLE} ${PUBLIC_API_TEST_SOURCES})

target_compile_definitions(${PUBLIC_TEST_EXECUTABLE}
    PRIVATE
        BUILD_PUBLIC_TESTS
)

target_include_directories(${PUBLIC_TEST_EXECUTABLE}
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/libs/osal/include
        ${CMAKE_SOURCE_DIR}/priv
)

target_link_libraries(${PUBLIC_TEST_EXECUTABLE}
    PRIVATE
        unit_test_framework
        el2go_rtp
        el2go_platform
        fwual
        el2go_ota_lib
        test_osal
)

# ============================================================================
# INTERNAL TEST EXECUTABLE
# ============================================================================

add_executable(${INTERNAL_TEST_EXECUTABLE} ${INTERNAL_API_TEST_SOURCES})

target_compile_definitions(${INTERNAL_TEST_EXECUTABLE}
    PRIVATE
        BUILD_INTERNAL_TESTS
)

target_include_directories(${INTERNAL_TEST_EXECUTABLE}
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/libs/el2go_rtp_lib
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/priv
        ${CMAKE_SOURCE_DIR}/libs/el2go_ota_lib/src
        ${CMAKE_SOURCE_DIR}/libs/protobuf/nanopb
        ${CMAKE_SOURCE_DIR}/libs/protobuf/ota
)

target_link_libraries(${INTERNAL_TEST_EXECUTABLE}
    PRIVATE
        unit_test_framework
        el2go_platform
        el2go_keystore
        el2go_datastore
        osal
        el2go_protobuf
        el2go_ota_lib
        pb_utils
        net_crypto
        el2go_common
        test_osal
)

# ============================================================================
# TEST REGISTRATION
# ============================================================================

# Include test definitions (registers tests with CTest)
include(cmake/test_definitions.cmake)

# ============================================================================
# INSTALLATION
# ============================================================================

# Install test executables to /usr/bin
install(TARGETS ${PUBLIC_TEST_EXECUTABLE} ${INTERNAL_TEST_EXECUTABLE}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# Install CMake's auto-generated CTestTestfile.cmake
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/CTestTestfile.cmake
    DESTINATION share/el2go/tests
)
