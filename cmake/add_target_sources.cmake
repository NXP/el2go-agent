# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

# Declares an OBJECT library
# Must be called before add_private_sources / add_private_directories
function(declare_library target)
    if(NOT BUILD_ZEPHYR)
        add_library(${target} OBJECT)
    endif()
endfunction()

# Adds private source files to a target
function(add_private_sources target)
    if(BUILD_ZEPHYR)
        zephyr_library_sources(${ARGN})
    else()
        target_sources(${target} PRIVATE ${ARGN})
    endif()
endfunction()

# Adds private include directories to a target
function(add_private_directories target)
    if(BUILD_ZEPHYR)
        zephyr_library_include_directories(${ARGN})
    else()
        target_include_directories(${target} PRIVATE ${ARGN})
    endif()
endfunction()

# Adds public include directories to a target
function(add_public_directories target)
    if(BUILD_ZEPHYR)
        zephyr_library_include_directories(${ARGN})
    else()
        target_include_directories(${target} PUBLIC ${ARGN})
    endif()
endfunction()

# Links libraries to a target
# Visibility keywords (PUBLIC, PRIVATE, INTERFACE) are passed through
# verbatim via ${ARGN} to target_link_libraries(), so callers must
# include the desired keyword explicitly, e.g.:
#   add_link_libraries(my_target PRIVATE foo)
#   add_link_libraries(my_target PUBLIC  bar)
function(add_link_libraries target)
    if(NOT BUILD_ZEPHYR)
        target_link_libraries(${target} ${ARGN})
    endif()
endfunction()

# Adds private compile definitions to a target
function(add_private_definitions target)
    if(BUILD_ZEPHYR)
        zephyr_library_compile_definitions(${ARGN})
    else()
        target_compile_definitions(${target} PRIVATE ${ARGN})
    endif()
endfunction()
