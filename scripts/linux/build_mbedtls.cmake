# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

include("${CMAKE_CURRENT_LIST_DIR}/cmake_policies.cmake")

if(NOT DEFINED CMAKE_FIND_LIBRARY_PREFIXES)
   set(CMAKE_FIND_LIBRARY_PREFIXES "lib")
endif()

if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    message(FATAL_ERROR "-DCMAKE_TOOLCHAIN_FILE=<toolchain file> missing")
endif()

# Root folder
if(NOT DEFINED MbedTLS_ROOT)
    message(FATAL_ERROR "-DMbedTLS_ROOT=<MbedTLS export path> missing")
endif()

if(NOT IS_ABSOLUTE ${MbedTLS_ROOT})
    set(MbedTLS_ROOT "${CMAKE_SOURCE_DIR}/${MbedTLS_ROOT}")
endif()

# build folder
if(NOT DEFINED MbedTLS_BUILD_DIR)
    message(FATAL_ERROR "-DMbedTLS_BUILD_DIR=<MbedTLS build path> missing")
endif()

if(NOT IS_ABSOLUTE ${MbedTLS_BUILD_DIR})
    set(MbedTLS_BUILD_DIR "${CMAKE_SOURCE_DIR}/${MbedTLS_BUILD_DIR}")
endif()

set(MbedTLS_BIN_DIR ${MbedTLS_ROOT}/usr)

include(${CMAKE_TOOLCHAIN_FILE})

# mbedTLS source is expected at ../mbedtls (sibling directory of this repository)
if(NOT DEFINED MbedTLS_SRC_PATH)
    message(FATAL_ERROR "-DMbedTLS_SRC_PATH=<MbedTLS source path> missing")
endif()

if(NOT IS_ABSOLUTE ${MbedTLS_SRC_PATH})
    set(MbedTLS_SRC_PATH "${CMAKE_SOURCE_DIR}/${MbedTLS_SRC_PATH}")
endif()

if(NOT EXISTS ${MbedTLS_SRC_PATH})
    message(FATAL_ERROR "MbedTLS source directory not found: ${MbedTLS_SRC_PATH}\n"
            "Clone https://github.com/nxp-imx/mbedtls.git "
            "as a sibling directory before running the build.")
endif()

find_package(Git QUIET)

# Log the exact mbedTLS commit for build traceability.
if(GIT_FOUND AND EXISTS "${MbedTLS_SRC_PATH}/.git")
    execute_process(
        COMMAND ${GIT_EXECUTABLE} -C ${MbedTLS_SRC_PATH} rev-parse HEAD
        OUTPUT_VARIABLE _mbedtls_commit
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
    )
    message(STATUS "MbedTLS source commit: ${_mbedtls_commit}")
endif()

set(ENV{CC} ${CMAKE_C_COMPILER})
set(ENV{AR} ${CMAKE_AR})

set(MbedTLS_BUILD_DIR ${MbedTLS_BUILD_DIR}/MbedTLS-build)

# Initialize git submodules required by the mbedTLS build (e.g. framework).
# Yocto fetches submodule contents separately; standalone builds must do this
# explicitly.
if(GIT_FOUND AND EXISTS "${MbedTLS_SRC_PATH}/.git")
    message(STATUS "Initializing MbedTLS git submodules in ${MbedTLS_SRC_PATH}")
    execute_process(
        COMMAND ${GIT_EXECUTABLE} submodule update --init
        WORKING_DIRECTORY ${MbedTLS_SRC_PATH}
        RESULT_VARIABLE submodule_result
    )
    if(NOT submodule_result EQUAL 0)
        message(FATAL_ERROR "Failed to initialize MbedTLS submodules (exit code: ${submodule_result})")
    endif()
endif()

# Configure MbedTLS
# Build options aligned with the Yocto recipe (meta-imx smw-3.6.x)
message(STATUS "Configuring MbedTLS from ${MbedTLS_SRC_PATH}")
execute_process(
    COMMAND ${CMAKE_COMMAND}
        -DENABLE_PROGRAMS=OFF
        -DMBEDTLS_FATAL_WARNINGS=OFF
        -DUSE_SHARED_MBEDTLS_LIBRARY=ON
        -DENABLE_TESTING=OFF
        -DCMAKE_INSTALL_PREFIX=${MbedTLS_BIN_DIR}
        -DCMAKE_C_FLAGS=-DMBEDTLS_USE_PSA_CRYPTO
        -DCMAKE_POSITION_INDEPENDENT_CODE=ON
        -S ${MbedTLS_SRC_PATH}
        -B ${MbedTLS_BUILD_DIR}
    RESULT_VARIABLE configure_result
)
if(NOT configure_result EQUAL 0)
    message(FATAL_ERROR "Failed to configure MbedTLS (exit code: ${configure_result})")
endif()

# Build MbedTLS
message(STATUS "Executing: ${CMAKE_COMMAND} --build ${MbedTLS_BUILD_DIR}")
execute_process(
    COMMAND ${CMAKE_COMMAND} --build ${MbedTLS_BUILD_DIR}
    RESULT_VARIABLE build_result
)
if(NOT build_result EQUAL 0)
    message(FATAL_ERROR "Failed to build MbedTLS (exit code: ${build_result})")
endif()

# Install MbedTLS
message(STATUS "Executing: ${CMAKE_COMMAND} --build ${MbedTLS_BUILD_DIR} --target install")
execute_process(
    COMMAND ${CMAKE_COMMAND} --build ${MbedTLS_BUILD_DIR} --target install
    RESULT_VARIABLE install_result
)
if(NOT install_result EQUAL 0)
    message(FATAL_ERROR "Failed to install MbedTLS (exit code: ${install_result})")
endif()
