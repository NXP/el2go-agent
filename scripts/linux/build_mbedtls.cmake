# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

include("${CMAKE_CURRENT_LIST_DIR}/cmake_policies.cmake")
include(FetchContent)

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

set(MbedTLS_BIN_DIR ${MbedTLS_ROOT}/usr/local/el2go)

include(${CMAKE_TOOLCHAIN_FILE})

list(APPEND CMAKE_MODULE_PATH PATHS ./cmake)
include(GNUInstallDirs)

find_package(MbedTLS MODULE)

if (MbedTLS_FOUND)
    message(STATUS "MbedTLS library already installed")
    return()
endif()

if(NOT DEFINED MbedTLS_SRC_PATH)
    message(FATAL_ERROR "-DMbedTLS_SRC_PATH=<MbedTLS source path> missing")
endif()

if(NOT IS_ABSOLUTE ${MbedTLS_SRC_PATH})
    set(MbedTLS_SRC_PATH "${CMAKE_SOURCE_DIR}/${MbedTLS_SRC_PATH}")
endif()

if(NOT EXISTS MBedTLS_REVISION)
    set(MbedTLS_BRANCH "development")
    set(MBedTLS_REVISION "2ca6c285a0dd3f33982dd57299012dacab1ff206")
endif()

set(MbedTLS_BUILD_DIR ${MbedTLS_BUILD_DIR}/MbedTLS-build)
# Download source using FetchContent_Populate with controlled directories
if(NOT EXISTS ${MbedTLS_SRC_PATH})
    message(STATUS "Download source for ${MbedTLS_SRC_PATH}")

    # MbedTLS patches
    set(MBedTLS_PATCH1 "https://raw.githubusercontent.com/nxp-imx/meta-imx/refs/heads/styhead-6.12.3-1.0.0/meta-imx-sdk/recipes-security/iot-agent/files/0001-crypto_struct-change-psa_key_attributes_t-layout.patch")
    set(MBedTLS_PATCH2 "https://raw.githubusercontent.com/nxp-imx/meta-imx/refs/heads/styhead-6.12.3-1.0.0/meta-imx-sdk/recipes-security/iot-agent/files/0002-library-tls-disable-PSA-APIs-for-most-operations.patch")

    # Extract patch filenames
    get_filename_component(PATCH1_NAME ${MBedTLS_PATCH1} NAME)
    get_filename_component(PATCH2_NAME ${MBedTLS_PATCH2} NAME)

    # Set up controlled temporary directory
    get_filename_component(MbedTLS_PARENT_DIR ${MbedTLS_SRC_PATH} DIRECTORY)
    set(TEMP_BUILD_DIR ${MbedTLS_PARENT_DIR}/mbedtls-fetchcontent-temp)

    FetchContent_Populate(
        mbedtls
        GIT_REPOSITORY https://github.com/Mbed-TLS/mbedtls.git
        GIT_TAG ${MBedTLS_REVISION}
        SOURCE_DIR ${MbedTLS_SRC_PATH}
        SUBBUILD_DIR ${TEMP_BUILD_DIR}/subbuild
        BINARY_DIR ${TEMP_BUILD_DIR}/binary
        PATCH_COMMAND
            wget -O ${PATCH1_NAME} ${MBedTLS_PATCH1} &&
            wget -O ${PATCH2_NAME} ${MBedTLS_PATCH2} &&
            git am ${PATCH1_NAME} &&
            git am ${PATCH2_NAME} &&
            git submodule update --init
    )

    # Clean up temporary files after successful download
    if(EXISTS ${TEMP_BUILD_DIR})
        message(STATUS "Cleaning up FetchContent temporary files")
        file(REMOVE_RECURSE ${TEMP_BUILD_DIR})
    endif()
endif()

set(ENV{CC} ${CMAKE_C_COMPILER})
set(ENV{AR} ${CMAKE_AR})

# configure MBedTLS
set(MbedTLS_CMAKE_ARGS
    -DENABLE_PROGRAMS=OFF
    -DMBEDTLS_FATAL_WARNINGS=OFF
    -DUSE_SHARED_MBEDTLS_LIBRARY=OFF
    -DENABLE_TESTING=OFF
    -DCMAKE_INSTALL_PREFIX=${MbedTLS_BIN_DIR}
    -DCMAKE_C_FLAGS="-DMBEDTLS_USE_PSA_CRYPTO"
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON)

# Configure MBedTLS
message(STATUS "Executing: ${CMAKE_COMMAND} ${MbedTLS_CMAKE_ARGS} -S ${MbedTLS_SRC_PATH} -B ${MbedTLS_BUILD_DIR}")
execute_process(
    COMMAND ${CMAKE_COMMAND} ${MbedTLS_CMAKE_ARGS} -S ${MbedTLS_SRC_PATH} -B ${MbedTLS_BUILD_DIR}
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

# Installing MBedTLS
message(STATUS "Executing: ${CMAKE_COMMAND} --build ${MbedTLS_BUILD_DIR} --target install")
execute_process(
    COMMAND ${CMAKE_COMMAND} --build ${MbedTLS_BUILD_DIR} --target install
    RESULT_VARIABLE install_result
)
if(NOT install_result EQUAL 0)
    message(FATAL_ERROR "Failed to install MbedTLS (exit code: ${install_result})")
endif()

if(NOT ${res} EQUAL 0)
    message(FATAL_ERROR "Cannot build MbedTLS: ${res}")
endif()
