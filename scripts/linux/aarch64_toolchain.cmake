# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR aarch64)
set(CMAKE_SIZEOF_VOID_P 8)

# Check if the current process is a try-compile operation.
# If it is, the compiler has already been set up, so we exit early
get_property(_IN_TC GLOBAL PROPERTY IN_TRY_COMPILE)
if(_IN_TC)
    return()
endif()

# Set the default aarch64 Cross-compiler toolchain
if(NOT TOOLCHAIN_NAME)
    set(TOOLCHAIN_NAME "aarch64-none-linux-gnu")
    set(TOOLCHAIN_VERSION "14.2.rel1" CACHE STRING "Default Toolchain Version")
    set(TOOLCHAIN_HASH "SHA256=47aeefc02b0ee39f6d4d1812110952975542d365872a7474b5306924bca4faa1")
    set(TOOLCHAIN_SERVER "https://developer.arm.com/-/media/Files/downloads/gnu/")
    set(TOOLCHAIN_URL ${TOOLCHAIN_SERVER}${TOOLCHAIN_VERSION}/binrel/)
endif()

#
# If Toolchain name and version are defined, create the
# Toolchain archive subdir where should be the toolchain
#
if(TOOLCHAIN_NAME AND TOOLCHAIN_VERSION)
    set(TOOLCHAIN_AR_DIR "arm-gnu-toolchain-${TOOLCHAIN_VERSION}-x86_64-${TOOLCHAIN_NAME}")
    set(TOOLCHAIN_SUBPATH ${TOOLCHAIN_AR_DIR}/bin)
endif()

find_program(GCC_BINTOOL NAMES ${TOOLCHAIN_NAME}-gcc PATHS ${TOOLCHAIN_PATH}
             PATH_SUFFIXES ${TOOLCHAIN_SUBPATH})
if(NOT GCC_BINTOOL AND FORCE_TOOLCHAIN_INSTALL)
    include(${CMAKE_SOURCE_DIR}/scripts/linux/install_toolchain.cmake)
    find_program(GCC_BINTOOL NAMES ${TOOLCHAIN_NAME}-gcc PATHS ${TOOLCHAIN_PATH}
                 PATH_SUFFIXES ${TOOLCHAIN_SUBPATH})
endif()

if(NOT GCC_BINTOOL)
    if(DEFINED TOOLCHAIN_PATH)
        message(FATAL_ERROR "\nToolchain ${TOOLCHAIN_NAME} not found in "
                "directory ${TOOLCHAIN_PATH}, fix path\n")
    else()
        message(FATAL_ERROR "\nToolchain ${TOOLCHAIN_NAME} not found. "
                "Either specified path on command line with `-DTOOLCHAIN_PATH=`,"
                " or add the toolchain path in the system environmnent PATH\n")
    endif()
endif()

set(TOOLCHAIN_PREFIX ${TOOLCHAIN_NAME}-)

get_filename_component(TOOLCHAIN_BIN_PATH ${GCC_BINTOOL} DIRECTORY CACHE)

set(CMAKE_C_COMPILER ${TOOLCHAIN_BIN_PATH}/${TOOLCHAIN_PREFIX}gcc)
set(CMAKE_ASM_COMPILER ${CMAKE_C_COMPILER})
set(CMAKE_CXX_COMPILER ${TOOLCHAIN_BIN_PATH}/${TOOLCHAIN_PREFIX}g++)

set(CMAKE_AR ${TOOLCHAIN_BIN_PATH}/${TOOLCHAIN_PREFIX}ar
    CACHE INTERNAL "archiving tool")
set(CMAKE_OBJCOPY ${TOOLCHAIN_BIN_PATH}/${TOOLCHAIN_PREFIX}objcopy
    CACHE INTERNAL "objcopy tool")
set(CMAKE_SIZE_UTIL ${TOOLCHAIN_BIN_PATH}/${TOOLCHAIN_PREFIX}size
    CACHE INTERNAL "size tool")

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

unset(GCC_BINTOOL CACHE)
