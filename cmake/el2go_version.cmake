# Copyright 2026 NXP
#
# SPDX-License-Identifier: Apache-2.0
#
# el2go_version.cmake
#
# Parse the three version components from include/common/el2go_version.h and
# expose them as CMake variables:
#
#   EL2GO_VERSION         -- full dotted string, e.g. "7.0.0"
#   EL2GO_VERSION_MAJOR   -- major component, e.g. "7"
#   EL2GO_VERSION_MINOR   -- minor component, e.g. "0"
#   EL2GO_VERSION_PATCH   -- patch component, e.g. "0"
#
# Include this script before the project() call and pass the result to
# project(... VERSION ${EL2GO_VERSION} ...) so that the shared-library
# VERSION/SOVERSION properties and the installed CMake package version file
# all stay in sync with the C macros without any duplication.

set(_EL2GO_VER_HEADER
    "${PROJECT_ROOT}/include/common/el2go_version.h")

if(NOT EXISTS "${_EL2GO_VER_HEADER}")
    message(FATAL_ERROR
        "el2go_version.cmake: version header not found: ${_EL2GO_VER_HEADER}")
endif()

file(STRINGS "${_EL2GO_VER_HEADER}" _line_MAJOR
    REGEX "^#define[ \t]+EL2GO_LIB_VERSION_MAJOR[ \t]+")
file(STRINGS "${_EL2GO_VER_HEADER}" _line_MINOR
    REGEX "^#define[ \t]+EL2GO_LIB_VERSION_MINOR[ \t]+")
file(STRINGS "${_EL2GO_VER_HEADER}" _line_PATCH
    REGEX "^#define[ \t]+EL2GO_LIB_VERSION_PATCH[ \t]+")

foreach(_component IN ITEMS MAJOR MINOR PATCH)
    string(REGEX REPLACE
        ".*EL2GO_LIB_VERSION_${_component}[ \t]+([0-9]+)[uUlL]*.*"
        "\\1"
        EL2GO_VERSION_${_component}
        "${_line_${_component}}")
    if(NOT EL2GO_VERSION_${_component} MATCHES "^[0-9]+$")
        message(FATAL_ERROR
            "el2go_version.cmake: could not parse ${_component} from "
            "${_EL2GO_VER_HEADER}")
    endif()
endforeach()

set(EL2GO_VERSION
    "${EL2GO_VERSION_MAJOR}.${EL2GO_VERSION_MINOR}.${EL2GO_VERSION_PATCH}")

# Clean up private helper variables so they do not leak into the parent scope.
unset(_EL2GO_VER_HEADER)
unset(_line_MAJOR)
unset(_line_MINOR)
unset(_line_PATCH)
unset(_component)
