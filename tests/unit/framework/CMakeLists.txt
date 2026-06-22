# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

# ============================================================================
# Unit Test Framework Library
# ============================================================================
# A lightweight test framework for unit testing
# Can be built as either STATIC or OBJECT library
# ============================================================================

# Option to choose library type
option(BUILD_TEST_FRAMEWORK_STATIC "Build test framework as static library" ON)

if(BUILD_TEST_FRAMEWORK_STATIC)
    set(FRAMEWORK_LIB_TYPE STATIC)
else()
    set(FRAMEWORK_LIB_TYPE OBJECT)
endif()

# Create the test framework library
add_library(unit_test_framework ${FRAMEWORK_LIB_TYPE}
    test_framework.c
    test_utils.c
)

target_include_directories(unit_test_framework
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
    PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/priv
        ${CMAKE_SOURCE_DIR}/libs/osal/include
)

target_link_libraries(unit_test_framework
    PUBLIC
        osal
)

# Print configuration
message(STATUS "Unit Test Framework Configuration:")
message(STATUS "  Library type: ${FRAMEWORK_LIB_TYPE}")
message(STATUS "  Library type: ${FRAMEWORK_LIB_TYPE}")