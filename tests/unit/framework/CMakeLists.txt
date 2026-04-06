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
)

# Public include directories
target_include_directories(unit_test_framework PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Print configuration
message(STATUS "Unit Test Framework Configuration:")
message(STATUS "  Library type: ${FRAMEWORK_LIB_TYPE}")