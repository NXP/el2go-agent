cmake_minimum_required(VERSION 3.15)
project(EL2GOAgents VERSION 1.0 LANGUAGES C)

# Include standard installation directories
include(GNUInstallDirs)

# Make project-local CMake modules available (e.g. add_target_sources)
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")


# Set default build type if not specified
if(NOT CMAKE_BUILD_TYPE)
    message(STATUS "Set default build type Release.")
    set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
else()
    message(STATUS "Build type ${CMAKE_BUILD_TYPE}.")
endif()

# Build shared library by default
option(BUILD_SHARED_LIBS "Build shared libraries" ON)

# Option to build applications
option(BUILD_APPLICATIONS "Build applications" ON)

# Option to build tests
option(BUILD_TESTING "Build tests" ON)

# Verbosity level for tracing
if(VERBOSE)
    if(NOT VERBOSE MATCHES "^[0-9]$")
        message(FATAL_ERROR "VERBOSE must be an integer")
    endif()

    if(NOT VERBOSE EQUAL 0)
        add_definitions(-DENABLE_TRACE)
    endif()

    if(${VERBOSE} GREATER 5)
        set(VERBOSE 5)
    endif()

    if(NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
        if(${VERBOSE} GREATER 2)
            set(VERBOSE 2)
        endif()
    endif()

    add_definitions(-DTRACE_LEVEL=${VERBOSE})
    message(STATUS TRACE_LEVEL: ${VERBOSE})
else()
    set(VERBOSE 0)
    add_definitions(-DTRACE_LEVEL=0)
endif()

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Set default OS if not defined
if(NOT DEFINED OS)
    set(OS linux)
endif()

# Set default platform if not defined
if(NOT DEFINED PLATFORM)
    set(PLATFORM smw)
endif()
message(STATUS "Using platform: ${PLATFORM}")

# Set crypto backend
if(NOT DEFINED CRYPTO_BACKEND)
    set(CRYPTO_BACKEND mbedtls)
endif()
message(STATUS "Using crypto backend: ${CRYPTO_BACKEND}")

# Enable compiler warnings
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wall -Wextra)
    option(ENABLE_WERROR "Treat warnings as errors" ON)
    if(ENABLE_WERROR)
        add_compile_options(-Werror)
    endif()
endif()

# Add library subdirectory
add_subdirectory(libs)

# Add applications if enabled
if(BUILD_APPLICATIONS)
    add_subdirectory(applications)
endif()

# Add tests if enabled
if(BUILD_TESTING)
    add_subdirectory(tests/unit)
endif()
