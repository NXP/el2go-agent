# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

# Wrappers that dispatch to the correct CMake API depending on whether
# we are building as a Zephyr module (BUILD_ZEPHYR=1) or as a plain
# CMake project (Linux / bare-metal).
#
# Usage:
#   add_private_sources(<target> file1.c file2.c ...)
#   add_private_directories(<target> dir1 dir2 ...)

function(add_private_sources target)
    if(BUILD_ZEPHYR)
        zephyr_library_sources(${ARGN})
    else()
        target_sources(${target} PRIVATE ${ARGN})
    endif()
endfunction()

function(add_private_directories target)
    if(BUILD_ZEPHYR)
        zephyr_library_include_directories(${ARGN})
    else()
        target_include_directories(${target} PRIVATE ${ARGN})
    endif()
endfunction()
