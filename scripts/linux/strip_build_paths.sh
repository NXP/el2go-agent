#!/bin/bash
#
# SPDX-License-Identifier: Apache-2.0 */
#
# Copyright 2026 NXP
#
# strip_build_paths.sh -- remove build-host paths from all CTestTestfile.cmake
# files found under a given directory to avoid Yocto buildpaths QA violations.
#
# Usage: strip_build_paths.sh <search-root>
#
# Two edits are applied to every CTestTestfile.cmake found:
#   1. Remove CMake-generated "# Source/Build directory:" comment lines.
#   2. Strip _BACKTRACE_TRIPLES values from set_tests_properties() calls.

set -e

ROOT="${1:-.}"

find "$ROOT" -name "CTestTestfile.cmake" | while read -r FILE; do
    echo "Stripping build paths from: $FILE"
    sed -i.bak "/^# \(Source\|Build\) directory:/d" "$FILE"
    sed -i.bak "s/ _BACKTRACE_TRIPLES .*)/)/g" "$FILE"
    rm -f "${FILE}.bak"
done
