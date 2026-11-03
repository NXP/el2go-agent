# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

cmake_minimum_required(VERSION 3.15)

# Make project-local CMake modules available (e.g. add_target_sources, el2go_version)
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

# Anchor PROJECT_ROOT before including el2go_version so the module can use it
# to locate the version header regardless of which directory calls include().
if(NOT DEFINED PROJECT_ROOT)
    set(PROJECT_ROOT "${CMAKE_SOURCE_DIR}")
endif()

# Parse the version from the single authoritative header.
# Must be included before project() so PROJECT_VERSION is set correctly.
include(el2go_version)

project(EL2GOAgents VERSION "${EL2GO_VERSION}" LANGUAGES C)
message(STATUS "EL2GO library version: ${PROJECT_VERSION}")

# Include standard installation directories
include(GNUInstallDirs)

# Include documentation build (Sphinx + Breathe + Doxygen).
# Only active when -DDOC_FORMAT=<html|xml|all> or -DDOC_ONLY=ON is passed.
add_subdirectory(doc)

# If objective is to build documentation only
if(DOC_ONLY)
    return()
endif()


# Top-level install namespace used as the include subdirectory for all public headers
set(EL2GO_AGENT_INSTALL_NAME "el2go-agent")


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

# Option to include the OTA library and OTA applications
option(BUILD_OTA "Build OTA library and OTA applications" OFF)
message(STATUS "BUILD_OTA: ${BUILD_OTA}")

# Option to build unit tests
option(BUILD_TESTING "Build unit tests" OFF)

# Verbosity level for tracing.
# Default is 2 (INFO) so that ERROR and INFO messages are visible out of the box.
# Pass -DVERBOSE=0 to silence all library output, or -DVERBOSE=3..5 for more.
if(VERBOSE)
    if(NOT VERBOSE MATCHES "^[0-9]$")
        message(FATAL_ERROR "VERBOSE must be an integer")
    endif()

    if(${VERBOSE} GREATER 5)
        set(VERBOSE 5)
    endif()

    if(NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
        if(${VERBOSE} GREATER 2)
            set(VERBOSE 2)
        endif()
    endif()
else()
    # No explicit VERBOSE given -- default to INFO level (ERROR + INFO visible)
    set(VERBOSE 2)
endif()

if(NOT VERBOSE EQUAL 0)
    add_compile_definitions(ENABLE_TRACE)
endif()
add_compile_definitions(TRACE_LEVEL=${VERBOSE})
message(STATUS "TRACE_LEVEL: ${VERBOSE}")

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

# Set default keystore if not defined
if(NOT DEFINED KEYSTORE)
    set(KEYSTORE psa)
endif()
message(STATUS "Using keystore: ${KEYSTORE}")

# CRL verification during RTP provisioning (default: enabled)
# The value is always passed explicitly so that the #ifndef guard in
# el2go_rtp_config.h cannot silently override a -DEL2GO_RTP_REQUEST_CRL=OFF
# selection made at configure time.
option(EL2GO_RTP_REQUEST_CRL "Request CRL verification during RTP provisioning" ON)
if(EL2GO_RTP_REQUEST_CRL)
    add_compile_definitions(EL2GO_RTP_REQUEST_CRL=1)
else()
    add_compile_definitions(EL2GO_RTP_REQUEST_CRL=0)
endif()
message(STATUS "EL2GO_RTP_REQUEST_CRL: ${EL2GO_RTP_REQUEST_CRL}")

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
    # Top-level aggregation targets for building and installing all tests.
    # The tests/unit subdirectory adds its own install_<project> target and
    # hooks it into these via add_dependencies().
    add_custom_target(build_tests)
    add_custom_target(install_tests)

    add_subdirectory(tests/unit)
endif()
