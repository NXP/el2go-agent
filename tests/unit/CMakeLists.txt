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

# Collect public RTP tests
add_subdirectory(public_rtp)
list(APPEND PUBLIC_TEST_SOURCES ${PUBLIC_TEST_SOURCES})

# Collect internal RTP tests
add_subdirectory(internal_rtp)
list(APPEND INTERNAL_TEST_SOURCES ${INTERNAL_TEST_SOURCES})

# Collect public datastore tests
add_subdirectory(public_datastore)
list(APPEND PUBLIC_TEST_SOURCES ${PUBLIC_TEST_SOURCES})

# Collect internal datastore tests
add_subdirectory(internal_datastore)
list(APPEND INTERNAL_TEST_SOURCES ${INTERNAL_TEST_SOURCES})

# ============================================================================
# Test sources organized by type
# ============================================================================

# Public API tests - only test what external users can access
set(PUBLIC_API_TEST_SOURCES
    main.c
    ${PUBLIC_TEST_SOURCES}
)

# Internal/implementation tests - test internal details
set(INTERNAL_API_TEST_SOURCES
    main.c
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
)

target_link_libraries(${PUBLIC_TEST_EXECUTABLE}
    PRIVATE
        unit_test_framework
        el2go_rtp
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
        ${CMAKE_SOURCE_DIR}/libs/datastores
        ${CMAKE_SOURCE_DIR}/libs/datastores/plain
        ${CMAKE_SOURCE_DIR}/libs/datastores/fs
        ${CMAKE_SOURCE_DIR}/libs/osal/include
)

target_link_libraries(${INTERNAL_TEST_EXECUTABLE}
    PRIVATE
        unit_test_framework
        _el2go_rtp_internal
)

# ============================================================================
# TEST REGISTRATION
# ============================================================================

# Include test definitions
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/test_definitions.cmake)

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
