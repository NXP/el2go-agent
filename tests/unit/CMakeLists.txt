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

# Collect OTA tests only when OTA support is enabled
if(BUILD_OTA)
    add_subdirectory(public_fwual)
    add_subdirectory(internal_fwual)
    add_subdirectory(mock)
    add_subdirectory(public_ota_lib)
    add_subdirectory(internal_ota_lib)
    add_subdirectory(public_ota_agent_core)
    add_subdirectory(internal_ota_agent_core)
    add_subdirectory(public_ota_agent_advanced)
    add_subdirectory(internal_ota_agent_advanced)
endif()

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

add_executable(${PUBLIC_TEST_EXECUTABLE} EXCLUDE_FROM_ALL ${PUBLIC_API_TEST_SOURCES})

target_compile_definitions(${PUBLIC_TEST_EXECUTABLE}
    PRIVATE
        BUILD_PUBLIC_TESTS
        BUILD_OTA=$<BOOL:${BUILD_OTA}>
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
        test_osal
)

if(BUILD_OTA)
    target_link_libraries(${PUBLIC_TEST_EXECUTABLE}
        PRIVATE
            fwual
            el2go_ota_lib
    )
endif()

# ============================================================================
# INTERNAL TEST EXECUTABLE
# ============================================================================

add_executable(${INTERNAL_TEST_EXECUTABLE} EXCLUDE_FROM_ALL ${INTERNAL_API_TEST_SOURCES})

target_compile_definitions(${INTERNAL_TEST_EXECUTABLE}
    PRIVATE
        BUILD_INTERNAL_TESTS
        BUILD_OTA=$<BOOL:${BUILD_OTA}>
)

target_include_directories(${INTERNAL_TEST_EXECUTABLE}
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/libs/el2go_rtp_lib
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/priv
        ${CMAKE_SOURCE_DIR}/libs/protobuf/nanopb
)

if(BUILD_OTA)
    target_include_directories(${INTERNAL_TEST_EXECUTABLE}
        PRIVATE
            ${CMAKE_SOURCE_DIR}/libs/el2go_ota_lib/src
            ${CMAKE_SOURCE_DIR}/libs/el2go_ota_lib/src/cred
            ${CMAKE_SOURCE_DIR}/libs/el2go_ota_lib/src/osal
            ${CMAKE_SOURCE_DIR}/libs/el2go_ota_lib/src/download
            ${CMAKE_SOURCE_DIR}/libs/el2go_ota_lib/src/transport
            ${CMAKE_SOURCE_DIR}/libs/protobuf/ota
            ${CMAKE_SOURCE_DIR}/tests/unit/mock
            ${CMAKE_SOURCE_DIR}/tests/unit/internal_ota_lib
    )
    target_link_libraries(${INTERNAL_TEST_EXECUTABLE}
        PRIVATE
            fwual
            el2go_ota_lib
    )
    target_sources(${INTERNAL_TEST_EXECUTABLE}
        PRIVATE
            ${FWUAL_MOCK_SOURCES}
            ${NET_CRYPTO_MOCK_SOURCES}
    )
endif()

target_link_libraries(${INTERNAL_TEST_EXECUTABLE}
    PRIVATE
        unit_test_framework
        el2go_platform
        el2go_keystore
        el2go_datastore
        osal
        el2go_protobuf
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
    EXCLUDE_FROM_ALL
    COMPONENT el2go_unit_tests
)

# Install CMake's auto-generated CTestTestfile.cmake
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/CTestTestfile.cmake
    DESTINATION share/el2go/tests
    EXCLUDE_FROM_ALL
    COMPONENT el2go_unit_tests
)

# install_${PROJECT_NAME} -- strip build-host paths from all CTestTestfile.cmake
# files under the build tree (via cmake/strip_build_paths.sh), then install the
# el2go_unit_tests component. Stripping prevents Yocto buildpaths QA violations.
add_custom_target(install_${PROJECT_NAME}
    COMMAND sh "${CMAKE_SOURCE_DIR}/scripts/linux/strip_build_paths.sh" "${CMAKE_BINARY_DIR}"
    COMMAND "${CMAKE_COMMAND}" -DCOMPONENT=el2go_unit_tests
            -P "${CMAKE_CURRENT_BINARY_DIR}/cmake_install.cmake"
    DEPENDS ${PUBLIC_TEST_EXECUTABLE} ${INTERNAL_TEST_EXECUTABLE}
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    VERBATIM
)

# Hook into the top-level build_tests / install_tests targets defined in the
# root CMakeLists.txt when BUILD_TESTING is ON.
if(TARGET build_tests)
    add_dependencies(build_tests ${PUBLIC_TEST_EXECUTABLE} ${INTERNAL_TEST_EXECUTABLE})
endif()

if(TARGET install_tests)
    add_dependencies(install_tests install_${PROJECT_NAME})
endif()
